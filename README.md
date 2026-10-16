<div align="center">

<p align="center">
  <strong>🇺🇸 English</strong> · <a href="./docs/locales/ko.md">🇰🇷 한국어</a> · <a href="./docs/locales/zh-CN.md">🇨🇳 中文</a> · <a href="./docs/locales/es.md">🇪🇸 Español</a> · <a href="./docs/locales/hi.md">🇮🇳 हिन्दी</a><br />
  <a href="./docs/locales/ar.md">🇸🇦 العربية</a> · <a href="./docs/locales/pt-BR.md">🇧🇷 Português</a> · <a href="./docs/locales/ru.md">🇷🇺 Русский</a> · <a href="./docs/locales/fr.md">🇫🇷 Français</a> · <a href="./docs/locales/id.md">🇮🇩 Bahasa Indonesia</a>
</p>

# shadow-vault (`svault`)

> Zero-trust steganography and dual-layer hardware-bound encrypted vault — conceal sensitive files inside ordinary PNG/audio carriers, seal them with Argon2id + ChaCha20-Poly1305 + Windows DPAPI, or embed dual-password plausible deniability decoy vaults.

[![Build](https://github.com/GHSFS/shadow-vault/actions/workflows/build.yml/badge.svg)](https://github.com/GHSFS/shadow-vault/actions/workflows/build.yml)
[![Tests](https://github.com/GHSFS/shadow-vault/actions/workflows/test.yml/badge.svg)](https://github.com/GHSFS/shadow-vault/actions/workflows/test.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](./LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20x64-0078D6)](#quick-start)

</div>

---

### Overview

`shadow-vault` (`svault.exe`) is a single-binary cryptographic vault and steganography toolkit written in Rust. It is built for operators who need robust protection for high-value files (seed phrases, private keys, credentials, research notes):

1. **Dual-Layer Authenticated Encryption (`SVLT` v1/v2)** — combines memory-hard **Argon2id** key derivation + **ChaCha20-Poly1305** AEAD with optional **Windows DPAPI (`CryptProtectData`)** machine/user-session binding. Even if an attacker steals both your `.svault` file and your passphrase, a DPAPI-bound vault cannot be decrypted outside your Windows user account.
2. **Plausible Deniability & Decoy Vaults (`src/decoy.rs`)** — embeds both a primary hidden secret (unlocked with the master passphrase) and a harmless decoy payload (unlocked with the decoy passphrase) within a single container. Under coercion, revealing the decoy passphrase unlocks only the decoy payload, while the primary hidden slot remains statistically indistinguishable from uniform random noise (CSPRNG padding and ChaCha20-Poly1305 ciphertext).
3. **Lossless Carrier Steganography** — embeds encrypted containers inside ordinary media files:
   - **PNG Images** — injects an `svLt` private ancillary chunk before `IEND` with valid IEEE 802.3 CRC-32 checksums.
   - **WAV Audio Files** — supports both RIFF/WAVE subchunk (`svLt`) and 16-bit PCM audio sample Least Significant Bit (LSB) replacement with CRC-32 validation.
   - **BMP Images (`src/bmp.rs`)** — modulates least significant bits (LSB) across 24-bit uncompressed RGB pixel channels with strict 4-byte row padding preservation and 12-byte tamper-resistant stego envelope (`svLt` magic, length, payload, CRC-32).
   - **MP3 Audio Files (`src/mp3/`)** — conceals encrypted payloads inside ID3v2.3/ID3v2.4 private (`PRIV`) tag frames or MPEG Audio Layer III inter-frame padding with frame sync validation, metadata preservation (TIT2, TPE1), CRC-32 integrity checking, and capacity estimation (`svault embed-mp3` / `svault extract-mp3`).
4. **Universal Carrier Capacity Estimation (`capacity`)** — calculates total and usable byte capacity across steganography carrier files (`.bmp`, `.wav`, `.png`, `.mp3`) with optional JSON output (`svault capacity <carrier> [--json]`).
5. **Shamir's Secret Sharing (`M-of-N` Key Splitting, `src/shamir.rs`)** — mathematically provable information-theoretic secret sharing over $\text{GF}(256)$ with constant-time arithmetic. Split master recovery keys, passphrases, or `.svault` containers into $N$ shares requiring any $M$ shares to reconstruct (`svault split` / `svault combine`).
6. **Passphrase Strength & Carrier Entropy Auditor (`src/audit.rs`)** — evaluates passphrase resiliency via Shannon entropy bits-per-byte, character pool diversity, and predictive vulnerability pattern detection (repeated characters, ascending/descending sequences, keyboard walks, leetspeak dictionary matching). Audits steganography carriers (PNG chunks, WAV RIFF/LSB streams, 24-bit BMP pixel LSB) and encrypted `.svault` containers for anomalies and tampering (`svault audit <target>` / `svault audit -p <passphrase>`).
7. **RFC 6238 TOTP 2FA Vault (`src/totp.rs`)** — zero-dependency encrypted local two-factor authentication secret store sealed inside `.svault` containers. Features RFC 4648 Base32 codec, self-contained RFC 3174 SHA-1, RFC 2104 HMAC (SHA-1/256/512), dynamic truncation, `otpauth://totp/...` URI parser/serializer, constant-time verification against timing attacks, and terminal visual countdown progress bar (`svault totp add`, `svault totp code`, `svault totp list`, `svault totp verify`).
8. **Auto-Expiring Clipboard Guard (`src/clipboard_guard.rs`)** — securely copies decrypted secrets, passwords, or TOTP tokens to the Windows clipboard with automatic suppression of Windows 10/11 Clipboard History and Cloud Sync (`CanIncludeInClipboardHistory`, `ExcludeClipboardContentFromMonitorProcessing`). Automatically wipes the clipboard after a configurable TTL (e.g., `--clip-ttl 15`) with constant-time SHA-256 fingerprint matching to avoid overwriting user clipboard changes made subsequently (`svault clip copy`, `svault clip paste`, `svault clip clear`, `svault clip status`, or `--clip` across decryption/extraction commands).
9. **Reed-Solomon / Parity Error-Correcting Armor (`src/armor.rs`)** — adds block parity recovery stripes and ASCII-armored `.svault.asc` export/import so containers survive partial bit rot or text transmission corruptions. Employs a Cauchy generator matrix $[I_K; A]$ over $\text{GF}(256)$ guaranteeing Maximum Distance Separable (MDS) erasure correction: ANY $K$ intact shards out of $K + M$ total stripes can reconstruct all original data shards. Supports automated corruption detection, self-healing document repair (`svault repair`), auto-detection in `inspect` and `audit`, and auto-expiring clipboard guard (`svault armor`, `svault dearmor`, `svault repair`).
10. **Directory & Multi-File Manifest Packing (`src/archive.rs`)** — packs entire directory trees with relative path canonicalization, multi-layered Zip Slip / path traversal prevention, zip bomb defense, per-file SHA-256 cryptographic manifests, and Unix/Windows permissions preservation into a single sealed `SVLT` container (`svault pack-dir` / `svault unpack-dir`). Supports `--list`, `--verify-only`, `--overwrite`, `--json`, `--dpapi`, and transparent stego (PNG/WAV/BMP) & ASCII armor carrier extraction.
11. **Keyfile + Passphrase Two-Factor Key Derivation (`src/keyfile.rs`)** — combines an external hardware or USB keyfile (`--keyfile <path>`) with user passphrases via streaming 64 KiB HMAC-SHA256 pre-hashing prior to Argon2id key derivation. Supports full 2FA (passphrase + keyfile) and keyfile-only operational modes, built-in CSPRNG keyfile generation (`svault keyfile generate`), SHA-256 fingerprinting (`svault keyfile fingerprint`), Shannon entropy inspection (`svault keyfile inspect`), and transparent integration across all steganography carriers and directory archiving.
12. **Chunked Streaming Encryption for Multi-GB Files (`src/stream.rs`)** — 4 MiB authenticated chunk streaming with per-chunk nonce derivation (`SVST` v1 container) for constant $O(1)$ memory usage on large archives, Windows DPAPI stream key protection, policy time-lock/expiration enforcement, transparent CLI streaming (`svault stream`), and automatic streaming container detection.
13. **Stego Carrier Visual & Statistical Diff Report (`src/diff.rs`)** — evaluates visual signal distortion (MSE, PSNR, MAE, pure LSB vs non-LSB flips), audio sample SNR/PSNR metrics, structural chunk table alignment, and information-theoretic divergence (Shannon entropy delta, total variation distance) between original and stego-bearing carrier files (`svault compare <original> <stego>`).
14. **Dead-Man's Switch & Maximum Attempt Self-Shred Guard (`src/guard.rs`)** — binds containers and carriers to a tamper-resistant attempt ledger (`.guard` companion or centralized stealth ledger). Automatically triggers multi-pass cryptographic shredding via `shred_file` if $K$ consecutive incorrect passphrase attempts occur or if an inactivity dead-man switch lapses without check-in (`svault guard arm`, `svault guard status`, `svault guard checkin`, `svault guard reset`, `svault guard trigger`).
15. **Deterministic & CSPRNG Passphrase Generator (`src/passgen/`)** — BIP-39 2,048-word Diceware recovery generator, character/symbol generator with visual ambiguity elimination (`--exclude-ambiguous`), raw CSPRNG byte tokens in Hex, Base64, and Base32 (`--bytes`), numeric PIN generation, master seed deterministic derivation (`--seed`, `--context`), multi-candidate generation, keyspace and empirical Shannon entropy evaluation with 5-tier resilience ratings, and auto-expiring clipboard guard integration (`svault keygen`).
16. **Unified Structured JSON Output Mode (`--json`)** — outputs clean, machine-readable JSON across all subcommands (`encrypt`, `decrypt`, `encrypt-decoy`, `decrypt-decoy`, `embed`, `extract`, `embed-wav`, `extract-wav`, `embed-bmp`, `extract-bmp`, `embed-mp3`, `extract-mp3`, `armor`, `dearmor`, `repair`, `shred`, `split`, `combine`, `keyfile`, `totp`, `clip`, `guard`, `pack-dir`, `unpack-dir`, `inspect`, `audit`, `compare`, `keygen`, `rotate`, `canary`) with consistent status, operation metrics, payload sizes, and cryptographic fingerprints for shell pipelines and CI/CD automation.
17. **Container Re-Key & Passphrase Rotation (`rotate`, `src/rotate.rs`)** — re-encrypts `.svault` containers and stego carriers (PNG, BMP, WAV, MP3, ASCII armor) with fresh CSPRNG salt and nonce, new passphrases or keyfiles, optional Windows DPAPI hardware binding toggles (`--dpapi`/`--no-dpapi`), temporal policy preservation or stripping (`--clear-policy`), and crash-resilient atomic file replacement (`svault rotate`).
18. **Detached Integrity Manifest & Canary Verification (`canary`, `src/canary.rs`)** — generates and verifies signed SHA-256 tamper canaries across directory trees of vaults and carriers (`svault canary init` / `svault canary verify`). Features multi-carrier format detection, optional Argon2id + HMAC-SHA256 signature authentication, constant-time verification, missing/modified/untracked anomaly reports, and machine-readable JSON output.
19. **MP3 ID3v2 & Audio Frame Steganography Engine (`src/mp3/`)** — provides robust steganographic embedding inside MPEG Audio Layer III files with ID3v2 PRIV private tag frame embedding, MPEG inter-frame padding embedding, transparent auto-detection, decoy plausible deniability, and carrier capacity estimation (`svault embed-mp3` / `svault extract-mp3`).
20. **FIDO2 & Windows Hello Hardware Key Credential Binding (`src/hardware_token/`)** — binds container encryption keys to physical FIDO2 USB security keys (YubiKey, SoloKey, Nitrokey, Titan Key), Windows Hello platform biometric credentials (TPM-backed), or virtual security tokens (`--fido2`, `--fido2-cred`, `--fido2-pin`). Cryptographically mixes the CTAP2 PRF (HMAC-secret) 32-byte secret with Argon2id base key material via domain-separated HMAC-SHA256, authenticating binary wire headers (`SVHW`) and CRC-32 integrity tags into ChaCha20-Poly1305 AEAD additional authenticated data (`aad`). Supports credential enrollment, registry management, assertion verification, and container rotation lifecycle (`svault fido2 enroll`, `svault fido2 list`, `svault fido2 test`, `svault fido2 remove`, `svault fido2 status`).
21. **Post-Quantum Hybrid Key Encapsulation (`src/pq_kem/`)** — dual-layer quantum-resistant asymmetric vault sealing combining classical **X25519** elliptic-curve Diffie-Hellman with NIST **FIPS 203 ML-KEM-768** (formerly Kyber-768). Derives symmetric ChaCha20-Poly1305 encryption keys via HKDF-SHA256 with strong domain separation, packaging payloads into authenticated `SVPQ` wire format containers with IEEE 802.3 CRC-32 integrity and PEM-style ASCII armoring (`svault kem keygen`, `svault kem seal`, `svault kem open`, `svault kem inspect`).
22. **Proactive Zeroize Hardening** — wipes sensitive intermediate key derivation buffers, ChaCha20 keys, Shamir polynomials, TOTP secrets, archive payload buffers, clipboard UTF-16 buffers, and DPAPI plaintext from memory upon drop using the `zeroize` crate.

### Features

- **Argon2id + ChaCha20-Poly1305 AEAD** — 128-bit random salt, 96-bit random nonce, domain-separated 256-bit key derivation, and 128-bit Poly1305 authentication tag.
- **Auto-Expiring Clipboard Guard (`clip`)** — secure credential clipboard transfer with automated destruction:
  - **Native Win32 Integration**: direct Win32 clipboard API calls (`OpenClipboard`, `EmptyClipboard`, `SetClipboardData`, `CloseClipboard`, `GetClipboardData`) with retry backoff.
  - **History & Cloud Sync Suppression**: writes Windows 10/11 privacy metadata formats (`CanIncludeInClipboardHistory`, `ExcludeClipboardContentFromMonitorProcessing`, `Clipboard Viewer Ignore`) to prevent persistent storage in clipboard history (Win + V) or Microsoft cloud synchronization.
  - **Constant-Time Verification**: branchless SHA-256 fingerprint verification (`constant_time_eq_32`) ensures the clipboard is only purged if it still holds the exact protected secret, preventing accidental scrubbing if the operator copied new text in the interim.
  - **Visual Countdown & Interactive Clearance**: dynamic terminal progress bar (`[████████░░] 12s remaining`), non-blocking instant Enter-to-clear shortcut, and silent daemon mode.
  - **Direct Command Integration**: `--clip` and `--clip-ttl <sec>` flags available on `decrypt`, `decrypt-decoy`, `extract`, `extract-wav`, and `totp code`.
- **RFC 6238 TOTP 2FA Vault (`totp`)** — encrypted multi-account two-factor authenticator:
  - **Zero External Dependencies**: self-contained Base32 codec (RFC 4648), RFC 3174 SHA-1, and RFC 2104 HMAC (SHA-1, SHA-256, SHA-512) verified against RFC 4226 Appendix D and RFC 6238 Appendix B test vectors.
  - **Hardware Binding & AEAD Protection**: account secrets stored inside `.svault` containers encrypted via Argon2id + ChaCha20-Poly1305 and optional Windows DPAPI.
  - **Key URI Interoperability**: full parsing and canonical serialization of standard `otpauth://totp/[Issuer:]Account?...` URIs.
  - **Constant-Time Verification**: sidechannel-resistant code verification (`constant_time_eq`) with configurable window skew tolerance ($\pm S$).
  - **Terminal UX & Visual Countdown**: colored code display, remaining seconds progress bar (`[████████░░] 19s`), and structured `--json` mode.
- **Passphrase Strength & Entropy Auditor (`audit`)** — deep security auditing for passwords, recovery phrases, and steganography carriers:
  - **Shannon & Pool Entropy**: computes exact bits-per-byte ($0.0 \le H \le 8.0$), total bits, and pool space entropy ($L \log_2 R$).
  - **Pattern & Vulnerability Detection**: detects sequential runs (`1234`, `abcd`), repetitions (`aaaa`), keyboard walks (`qwerty`, `asdfgh`), and leetspeak dictionary matches (`p@ssw0rd`).
  - **Multi-Vector Crack Time Estimations**: online rate-limited (100/s), offline Argon2id ($10^3$/s), and offline GPU hash cluster ($10^{10}$/s).
  - **Steganography Carrier Steganalysis**: inspects PNG chunks, trailing data past `IEND`, WAV RIFF `svLt` subchunks, and 16-bit PCM LSB stream headers with Chi-Square ($\chi^2$) uniformity testing.
  - **Structured JSON Mode (`--json`)**: outputs machine-readable reports for automated security pipelines.
- **Shamir's Secret Sharing ($M$-of-$N$ Key Splitting)** — split secrets into $2 \le M \le N \le 255$ shares over $\text{GF}(256)$:
  - **Constant-Time Field Arithmetic**: branchless peasant multiplication and Fermat inversion ($a^{-1} = a^{254}$) with zero secret-dependent table lookups.
  - **Dual-Layer Integrity**: embedded SHA-256 secret digest ensures tampered shares cannot forge valid secrets; per-share CRC-32 detects transmission corruption.
  - **Flexible Serialization**: ASCII armored blocks (`-----BEGIN SHADOW VAULT SHARE-----`), single-line compact strings (`SVLT-S1-...`), and structured JSON.
- **Plausible Deniability Dual-Password Containers** — store primary classified data and harmless decoy data in one `.svault` container:
  - **Seamless Decryption**: `svault decrypt -p <passphrase>` automatically detects and unlocks whichever slot matches the supplied passphrase.
  - **Indistinguishable Hidden Slot**: no plaintext magic headers or length fields for the hidden volume; trailer bytes have maximal Shannon entropy (~8.0 bits/byte).
  - **Size Obfuscation & Padding (`--padding <bytes>`)**: append explicit CSPRNG random padding or default 256-byte alignment to prevent file size analysis.
- **Hardware / Session Binding (`--dpapi`)** — wraps ciphertext with Windows DPAPI so decryption is restricted to the originating Windows user profile without leaking DPAPI metadata into hidden volumes.
- **Proactive Memory Zeroization (`zeroize`)** — sensitive key schedules and plaintext buffers are wiped with compiler-fence memory zeroes on drop.
- **Lossless PNG Steganography (`embed` / `extract`)** — injects an `svLt` ancillary chunk before `IEND` with full CRC-32 verification; supports direct decoy vault embedding (`--decoy` and `--decoy-passphrase`).
- **WAV Audio Steganography (`embed-wav` / `extract-wav`)** — dual-mode WAV concealment:
  - **RIFF Subchunk Mode (`--mode chunk`)**: attaches dedicated `svLt` metadata chunk with CRC-32.
  - **16-bit PCM LSB Mode (`--lsb` / `--mode lsb`)**: alters least significant bit of 16-bit samples for inaudible acoustic concealment without changing file length.
  - **Auto Detection**: `extract-wav` automatically detects and unpacks both subchunk and LSB carriers.
- **BMP 24-bit Pixel LSB Steganography (`embed-bmp` / `extract-bmp`)** — bit-level LSB concealment:
  - **Row Stride Padding Preservation**: accurately navigates 4-byte row alignment padding, embedding data exclusively in R, G, B color channels without corrupting row strides.
  - **Tamper-Resistant 12-Byte Envelope**: frames embedded payloads inside `[svLt: 4B][len: 4B LE][payload: NB][crc32: 4B LE]` with constant-time CRC-32 validation.
  - **Carrier Audit & Steganalysis**: integrates with `svault audit` to verify pixel LSB integrity and detect payload presence.
  - **Decoy & Clipboard Integration**: supports plausible deniability decoy vaults (`--decoy`, `--decoy-passphrase`) and clipboard guard auto-expiration (`--clip`, `--clip-ttl`).
- **Reed-Solomon / Parity Error-Correcting Armor (`armor` / `dearmor` / `repair`)** — robust container error correction and ASCII armor:
  - **Cauchy MDS Reed-Solomon over $\text{GF}(256)$**: uses generator matrix $[I_K; A]$ with Cauchy entries $A_{i, j} = \frac{1}{(K + i) \oplus j}$. Any $K$ intact shards out of $K + M$ stripes reconstruct all data shards via Gaussian elimination in $\text{GF}(256)$.
  - **Per-Stripe CRC-32 & SHA-256 Binding**: each stripe has individual CRC-32 validation for precise erasure localization; overall container payload is authenticated by SHA-256.
  - **Self-Healing Repair Subcommand (`repair`)**: reconstructs damaged stripes and outputs a refreshed `.svault.asc` document or exports directly to binary (`--binary`) with full `--json` diagnostics.
  - **Transparent Recovery in `dearmor`**: automatically invokes Cauchy RS erasure reconstruction if any data stripes are corrupted in transit.
  - **Auto-Detection in `inspect` & `audit`**: inspects stripe health and audits CRC-32 integrity across all data and parity blocks.
- **Directory & Multi-File Manifest Packing (`pack-dir` / `unpack-dir`)** — sealed container archiving with security hardening:
  - **`SVAR` Binary Architecture**: 18-byte header (`SVAR` v1), per-entry metadata, individual SHA-256 digests, and trailing 8-byte CRC-32 checksum with `SVEN` magic.
  - **Path Traversal & Zip Slip Prevention**: canonicalizes relative paths to `/`, rejects `..`, absolute/UNC paths, drive prefixes, ADS colon streams, null bytes, and Windows reserved device names (`CON`, `PRN`, `AUX`, `NUL`, `COM1..9`, `LPT1..9`).
  - **Decompression Bomb Defense**: hard caps on archive size (8 GiB), single file size (4 GiB), entry count (100,000), path length (4,096), and nesting depth (64 levels), with bounds checks before allocating buffers.
  - **Flexible Manifest CLI**: `--list` displays table/JSON of archive contents, `--verify-only` cryptographically validates per-file SHA-256 digests in memory, and `--overwrite` controls destination replacement.
  - **Transparent Carrier & Armor Extraction**: `unpack-dir` automatically dearmors `.svault.asc` documents and extracts from PNG, WAV, or BMP stego carriers.
- **Universal Carrier Capacity Estimation (`capacity`)** — calculates total carrier capacity, usable payload capacity, and stego overhead bytes across `.bmp`, `.wav`, and `.png` carriers with optional `--json` machine-readable output.
- **Zero-Knowledge Header Inspection (`inspect`)** — view container version, DPAPI binding flag, decoy container presence, payload byte size, and salt hex across `.svault`, `.png`, `.wav`, and `.bmp` files without decrypting or exposing hidden slot sizes.
- **Time-Lock & Expiration Policy Headers (`policy`)** — embed cryptographically bound temporal access policies directly into encrypted containers:
  - **Authenticated Policy Header (`SVPO`)**: 28-byte canonical header with magic `SVPO`, version 1, flags (`HAS_NOT_BEFORE`, `HAS_EXPIRES_AT`, `HAS_DESCRIPTION`), `created_at`, `not_before`, `expires_at`, optional UTF-8 description, and CRC-32 validation.
  - **AEAD AAD Binding**: the entire binary policy block is injected as Additional Authenticated Data (`aad`) into ChaCha20-Poly1305. Any modification or tampering with policy timestamps or descriptions invalidates the Poly1305 MAC tag and causes immediate authentication failure.
  - **Temporal Access Enforcement**: vaults sealed with `--not-before` refuse decryption with `TimeLocked` until the threshold is reached; vaults sealed with `--expires-at` or `--expires-in` refuse decryption with `Expired` once the lifetime has elapsed.
  - **Flexible Temporal Syntax**: accepts Unix epoch seconds (`1791850000`), ISO-8601 UTC date/time (`2026-10-15T00:00:00Z`, `2026-12-31`), or relative durations (`+1h`, `+7d`, `+30m`, `+1y`).
  - **Inspection & Auditing Integration**: `inspect` displays policy status (`ACTIVE`, `TIMELOCKED`, `EXPIRED`), remaining or elapsed seconds, human-readable UTC timestamps, and description, with full `--json` support. `audit` parses policy headers and tracks ciphertext entropy offsets accordingly.
- **Keyfile + Passphrase Two-Factor Derivation (`keyfile`)** — cryptographically bind physical USB tokens or external files to container encryption:
  - **Streaming 64 KiB HMAC-SHA256**: reads keyfiles of arbitrary size (16 bytes up to multi-megabyte files) in a constant-memory 64 KiB zeroized buffer.
  - **Cryptographic 2FA & Keyfile-Only Modes**: 2FA derives key material via `HMAC-SHA256(key = passphrase, data = "shadow-vault:keyfile-v1:" || keyfile_stream)`, while keyfile-only derives via domain separator `b"shadow-vault:keyfile-only:v1"`, feeding a 256-bit high-entropy seed into Argon2id.
  - **CSPRNG Keyfile Generator (`svault keyfile generate`)**: creates cryptographically secure hardware keyfiles (default 64 bytes) via `rand::rngs::OsRng`.
  - **Keyfile Inspection & Fingerprint (`inspect` / `fingerprint`)**: computes SHA-256 fingerprints (`SHA256:<hex>`) and Shannon entropy quality ratings with sample-size normalization.
  - **Universal Command Binding**: `--keyfile` / `-k` supported across `encrypt`, `decrypt`, `embed`, `extract`, `embed-wav`, `extract-wav`, `embed-bmp`, `extract-bmp`, `embed-mp3`, `extract-mp3`, `pack-dir`, `unpack-dir`, and decoy vaults.
- **Chunked Streaming Encryption (`stream`)** — constant $O(1)$ memory streaming authenticated encryption:
  - **`SVST` v1 Wire Format**: 38-byte base header (magic `SVST`, version 1, flags, chunk size, salt, base nonce) with optional `SVPO` policy header and DPAPI wrapped stream key.
  - **Chunk Nonce & AAD Derivation**: unique nonce per chunk preventing IV reuse; AAD incorporates chunk index, intermediate/final tag, salt, and policy hash to eliminate chunk reordering, truncation, or substitution.
  - **Zero Whole-File Buffering**: 2-buffer sliding window processes arbitrarily large files (0 bytes to multi-gigabytes) without memory exhaustion.
  - **Transparent Auto-Detection**: `svault decrypt` and `svault inspect` automatically recognize streaming containers and dispatch to the streaming engine.
- **Stego Carrier Visual & Statistical Diff Report (`compare` / `diff`)** — compare reference carriers against stego-bearing media across visual, acoustic, and statistical dimensions:
  - **Visual Image Quality (MSE & PSNR)**: evaluates pixel channel errors, peak signal-to-noise ratio in dB, mean absolute error (MAE), altered pixel count/ratio, and bit flip distributions (LSB vs non-LSB).
  - **Acoustic Audio Quality (SNR & PSNR)**: evaluates 16-bit PCM sample errors, signal-to-noise ratio in dB, and sample alteration ratios for WAV audio carriers.
  - **Structural Chunk Table Comparison**: inspects PNG ancillary chunks and WAV RIFF subchunks, identifying injected `svLt` metadata, offset locations, and byte lengths.
  - **Information-Theoretic & Histogram Divergence**: computes Shannon entropy shifts ($\Delta H$), 256-bin byte frequency Total Variation Distance (TVD), Chi-Square divergence ($\chi^2$), and Hamming distance bit flips.
  - **Structured JSON & Detailed Inspection**: supports `--json` for automated security pipelines and `--detailed` for modified byte spans and histogram deltas.
- **Dead-Man's Switch & Max-Attempt Self-Destruction Guard (`guard`)** — active defense against unauthorized access:
  - **Configurable Attempt Threshold**: arm containers with a maximum failed passphrase limit (`--max-attempts 3`). Successful authentication resets failed attempt counters to zero.
  - **Cryptographic Multi-Pass Self-Shredding**: upon reaching threshold $K$, executes 3-pass DoD-style cryptographic overwrite (`0x00`, `0xFF`, CSPRNG), flushes hardware file buffers (`sync_all`), and unlinks the target file permanently.
  - **Dead-Man Switch Inactivity Timer**: configure deadline durations (`--dead-man 7d`, `24h`). If an operator fails to check in before the deadline (`svault guard checkin`), the vault automatically shreds on the next access attempt.
  - **Stealth Ledger & Companion Modes**: defaults to stealth storage in user profile directories (`~/.shadow-vault/guards/<path_hash>.guard`) to prevent adversaries from detecting active guards, or portable companion files (`<target>.guard`).
  - **Tamper-Evident Signatures**: every ledger update signs state using SHA-256 with machine-bound seeds. Malicious manual modifications to counter values are rejected with `tampering detected`.
  - **Carrier & Archive Transparency**: guards can be armed across standard `.svault` containers, streaming files, or steganography carriers (PNG, WAV, BMP).
- **Deterministic & CSPRNG Passphrase Generator (`keygen` / `passgen`)** — generate high-entropy recovery phrases and cryptographic tokens:
  - **BIP-39 Diceware Engine (`--words 6`)**: selects from curated 2,048-word English dictionary (11.0 bits entropy per word), with customizable delimiters (`--separator`), TitleCase capitalization (`--capitalize`), and inline numeric padding (`--number`).
  - **Customizable Character Passphrases (`--length 20`)**: configurable inclusion of symbols, digits, and uppercase letters with guaranteed class diversity and visual ambiguity elimination (`--exclude-ambiguous` removes `0`, `O`, `o`, `1`, `l`, `I`, `8`, `B`, `|`).
  - **Raw Cryptographic Byte Tokens (`--bytes 32`)**: outputs raw CSPRNG bytes in hexadecimal, standard Base64 (`--base64`), or RFC 4648 Base32 (`--base32`, compatible with TOTP seeds).
  - **Deterministic Seed Derivation (`--seed`, `--context`)**: derives reproducible passphrases from a master seed and service context using HMAC-SHA256, allowing operators to deterministically regenerate credentials.
  - **Entropy Rating & Vulnerability Assessment (`--entropy`)**: classifies keyspace entropy across five tiers (Weak to Military Grade), computes Shannon entropy, and estimates crack times across online, Argon2id, and GPU threat models.
  - **Auto-Expiring Clipboard Guard (`--clip`, `--clip-ttl`)**: copies secrets directly to system clipboard with memory auto-wiping and Windows clipboard history suppression.
- **Interactive Terminal Vault Shell (`repl` / `shell`)** — in-memory Read-Eval-Print Loop for key-value secrets: unlocks containers once into memory, supports `get`, `set`, `del`, `list`, `export`, and `import` without writing plaintext to disk, with auto-expiring clipboard integration (`--clip`), read-only auditing (`--readonly`), batch command execution (`--exec`), and crash-resilient atomic re-encryption.
- **3-Pass Secure File Shredder (`shred`)** — overwrites sensitive plaintext files with `0x00`, `0xFF`, and CSPRNG random bytes before unlinking.
- **Single Static Binary** — compiled with `+crt-static`, `opt-level = "z"`, LTO, and stripped symbols. Zero external runtime dependencies.

### Architecture

```text
  [ Primary Secret ] ──▶ [ ChaCha20-Poly1305 + CSPRNG Pad ] ──┐ (Hidden Slot)
                                                                 │
  [ Decoy Payload ]  ──▶ [ ChaCha20-Poly1305 Encrypted ]     ──┴─▶ SVLT v2 Container (.svault)
                                                                        ├── Direct disk storage
                                                                        └── Stego Carrier
                                                                              ├── PNG Image (.png)
                                                                              ├── WAV Audio (.wav)
                                                                              └── BMP Image (.bmp)
```

### Quick Start

```bash
# 1. Encrypt a file with passphrase + Windows DPAPI hardware binding
svault encrypt -i wallet-seed.txt -o wallet.svault -p "your-strong-passphrase" --dpapi

# 2. Encrypt a plausible deniability vault with both hidden secret and decoy payload
svault encrypt -i classified.txt --decoy shopping-list.txt -o deniable.svault \
  -p "primary-secret-pass" --decoy-passphrase "decoy-harmless-pass" --padding 512

# 3. Decrypt deniable container (supplying decoy password unlocks only shopping list)
svault decrypt -i deniable.svault -o revealed.txt -p "decoy-harmless-pass"
# Supplying primary password unlocks the true secret
svault decrypt -i deniable.svault -o restored.txt -p "primary-secret-pass"

# 4. Inspect container metadata without decrypting (.svault, .png, .wav, or .bmp)
svault inspect deniable.svault

# 5. Conceal a dual-password decoy vault directly inside a PNG image
svault embed -c wallpaper.png -s classified.txt --decoy shopping-list.txt -o wallpaper-stego.png \
  -p "primary-secret-pass" --decoy-passphrase "decoy-harmless-pass"

# 6. Extract secret from PNG (extract with primary or decoy passphrase)
svault extract -c wallpaper-stego.png -o restored-seed.txt -p "primary-secret-pass"
svault extract -c wallpaper-stego.png -o decoy-seed.txt --decoy-passphrase "decoy-harmless-pass"

# 7. Conceal a secret inside a WAV audio file (RIFF subchunk or 16-bit PCM LSB)
svault embed-wav -c track.wav -s classified.txt -o track-lsb.wav -p "primary-secret-pass" --lsb

# 8. Extract and decrypt secret from WAV audio file (auto-detects chunk or LSB)
svault extract-wav -c track-lsb.wav -o restored-audio.txt -p "primary-secret-pass"

# 9. Estimate carrier capacity for steganography embedding (.bmp, .wav, .png, or .mp3)
svault capacity landscape.bmp
svault capacity track.wav --json
svault capacity song.mp3

# 10. Conceal secret inside a 24-bit BMP image via pixel LSB steganography
svault embed-bmp -c landscape.bmp -s classified.txt -o landscape-stego.bmp -p "primary-secret-pass"

# 11. Extract secret from BMP image directly to auto-expiring clipboard
svault extract-bmp -c landscape-stego.bmp -p "primary-secret-pass" --clip --clip-ttl 15

# 12. Conceal secret inside an MP3 audio file (ID3v2 PRIV tag or inter-frame padding)
svault embed-mp3 -c song.mp3 -s classified.txt -o song-stego.mp3 -p "primary-secret-pass" --mode id3v2
svault embed-mp3 -c song.mp3 -s classified.txt -o song-frame.mp3 -p "primary-secret-pass" --mode frame

# 13. Extract secret from MP3 audio file (auto-detects ID3v2 or frame mode)
svault extract-mp3 -c song-stego.mp3 -o restored-mp3.txt -p "primary-secret-pass"

# 12. Securely shred the original plaintext file (3 passes)
svault shred classified.txt --passes 3

# 13. Split a master recovery key or secret into 3-of-5 Shamir shares
svault split -s "your-master-seed-or-secret" -m 3 -n 5 -o shares/share

# 14. Combine any 3 shares to reconstruct the original secret
svault combine shares/share_1.share shares/share_3.share shares/share_5.share -o restored.txt

# 15. Audit passphrase strength, Shannon entropy, and crack time estimates
svault audit -p "Correct-Horse-Battery-Staple-2026!"

# 16. Audit a stego carrier image or container for anomalies and hidden payloads
svault audit wallpaper-stego.png --json

# 17. Add a TOTP 2FA credential via Base32 secret or otpauth:// URI
svault totp add github --secret "JBSWY3DPEHPK3PXP" --issuer "GitHub" --vault totp.svault -p "vault-pass"
svault totp add --uri "otpauth://totp/Google:alice?secret=JBSWY3DPEHPK3PXP&issuer=Google" --vault totp.svault -p "vault-pass"

# 18. Generate live 2FA OTP code with visual countdown progress bar (or --json)
svault totp code github --vault totp.svault -p "vault-pass"
svault totp code github --vault totp.svault -p "vault-pass" --json

# 19. Verify an OTP code against skew window (+/- 1 step)
svault totp verify github 123456 --skew 1 --vault totp.svault -p "vault-pass"

# 20. List and export 2FA accounts
svault totp list --vault totp.svault -p "vault-pass"
svault totp export github --vault totp.svault -p "vault-pass"

# 21. Copy a secret to clipboard with 15-second auto-expiring guard (or silent mode)
svault clip copy "my-super-secret-password" --ttl 15
svault clip copy "my-super-secret-password" --ttl 15 --silent

# 22. Check clipboard status and history exclusion metadata, or manually clear
svault clip status
svault clip clear

# 23. Decrypt directly to protected clipboard without printing to terminal or writing plaintext to disk
svault decrypt -i secret.svault -p "vault-pass" --clip --clip-ttl 30
svault totp code github --vault totp.svault -p "vault-pass" --clip --clip-ttl 15

# 24. Armor a .svault container with Cauchy Reed-Solomon parity stripes (.svault.asc)
svault armor -i secret.svault -o secret.svault.asc -k 4 -m 2

# 25. Decode an ASCII armored file back to original .svault container
svault dearmor -i secret.svault.asc -o recovered.svault

# 26. Repair a corrupted .svault.asc file using Cauchy Reed-Solomon parity
svault repair -i corrupted.svault.asc -o repaired.svault.asc --json
svault repair -i corrupted.svault.asc -o direct_recovered.svault --binary

# 27. Inspect and audit ASCII armored container stripes and integrity
svault inspect secret.svault.asc
svault audit secret.svault.asc --json

# 28. Pack an entire directory tree into an encrypted .svault container
svault pack-dir -i ./my_project -o project.svault -p "pack-passphrase" --list

# 29. Pack into a stego carrier (PNG, WAV, BMP, MP3) or ASCII armor
svault pack-dir -i ./my_project -o project.png -p "pack-passphrase" --carrier cover.png
svault pack-dir -i ./my_project -o project.svault.asc -p "pack-passphrase" --armor

# 30. Unpack, inspect archive manifest, or verify cryptographic digests
svault unpack-dir -i project.svault -p "pack-passphrase" --list
svault unpack-dir -i project.svault -p "pack-passphrase" --verify-only
svault unpack-dir -i project.svault -o ./restored_project -p "pack-passphrase" --overwrite

# 31. Encrypt with time-lock escrow (cannot be opened until future date)
svault encrypt -i escrow.txt -o escrow.svault -p "vault-pass" --not-before "2026-12-31T00:00:00Z" --policy-desc "Year-End Escrow"

# 32. Encrypt with auto-expiring policy (expires in 2 hours or specific ISO date)
svault encrypt -i token.txt -o token.svault -p "vault-pass" --expires-in 2h --policy-desc "Session Token"
svault encrypt -i doc.txt -o doc.svault -p "vault-pass" --expires-at "2026-10-15"

# 33. Inspect policy metadata without decrypting (human-readable and JSON)
svault inspect escrow.svault
svault inspect escrow.svault --json

# 34. Decrypt testing against an explicit reference timestamp
svault decrypt -i escrow.svault -o restored.txt -p "vault-pass" --at-time "2027-01-01"

# 35. Generate a cryptographic USB keyfile (CSPRNG, default 64 bytes)
svault keyfile generate -o usb_token.key --bytes 64

# 36. Inspect keyfile fingerprint and Shannon entropy (text and JSON)
svault keyfile inspect usb_token.key
svault keyfile inspect usb_token.key --json
svault keyfile fingerprint usb_token.key

# 37. Encrypt and decrypt with 2FA (Passphrase + Keyfile)
svault encrypt -i secret.txt -o sealed.svault -p "master-pass" -k usb_token.key
svault decrypt -i sealed.svault -o restored.txt -p "master-pass" -k usb_token.key

# 38. Keyfile-only encryption without password
svault encrypt -i token.txt -o hardware.svault -k usb_token.key
svault decrypt -i hardware.svault -o restored.txt -k usb_token.key

# 39. Pack directory into encrypted vault with Keyfile 2FA
svault pack-dir -i ./confidential -o archive.svault -p "pack-pass" -k usb_token.key
svault unpack-dir -i archive.svault -o ./unpacked -p "pack-pass" -k usb_token.key

# 40. Encrypt a multi-gigabyte file with chunked streaming (default 4 MiB chunks or custom)
svault stream encrypt -i large_dataset.iso -o large_dataset.svault -p "stream-pass"
svault encrypt -i database.backup -o db.svault -p "stream-pass" --stream --chunk-size 8M

# 41. Decrypt streaming container (auto-detects SVST format or explicit stream subcommand)
svault decrypt -i large_dataset.svault -o restored.iso -p "stream-pass"
svault stream decrypt -i db.svault -o restored_db.backup -p "stream-pass"

# 42. Inspect streaming container metadata without decrypting
svault stream inspect large_dataset.svault
svault inspect large_dataset.svault --json

# 43. Compare original carrier against stego-bearing carrier (PNG, BMP, WAV, or binary)
svault compare cover.bmp stego.bmp
svault compare cover.png stego.png --json
svault diff original.wav stego.wav --detailed

# 44. Arm a vault with a 3-attempt self-shredding guard and dead-man switch
svault encrypt -i secret.txt -o guarded.svault -p "vault-pass" --max-attempts 3 --dead-man 7d --guard-companion

# 45. Arm an existing carrier or vault file directly
svault guard arm -t stego.png --max-attempts 3 --companion
svault guard arm -t vault.svault --max-attempts 5 --dead-man 24h

# 46. Inspect guard status and remaining attempts (human-readable and JSON)
svault guard status -t guarded.svault
svault guard status -t guarded.svault --json

# 47. Check-in to refresh dead-man switch deadline or reset attempt counter
svault guard checkin -t guarded.svault --interval 30d
svault guard reset -t guarded.svault

# 48. Disarm a guard or trigger emergency multi-pass file shredding
svault guard disarm -t guarded.svault
svault guard trigger -t guarded.svault --force --passes 3

# 49. Generate a 6-word BIP-39 Diceware recovery passphrase
svault keygen --words 6

# 50. Generate customized Diceware with numbers and capitalization
svault keygen --words 4 --separator "." --capitalize --number

# 51. Generate 24-character password with ambiguity filter and entropy analysis
svault keygen --length 24 --exclude-ambiguous --entropy

# 52. Deterministic passphrase derivation from master seed and service context
svault keygen --words 6 --seed "master-recovery-seed" --context "github-token"

# 53. Generate raw 32-byte cryptographic token (Base64 or Base32) and copy to clipboard
svault keygen --bytes 32 --base64 --clip --clip-ttl 30
svault keygen --bytes 20 --base32 --json

# 54. Re-key container with new passphrase, fresh salt & nonce
svault rotate -i vault.svault -o rotated.svault -p "old-secret" -n "new-secret"

# 55. Re-key container or carrier in-place atomically
svault rotate -i vault.svault --in-place -p "old-secret" -n "new-secret"
svault rotate -i stego.bmp --in-place -p "old-pass" -n "new-pass"

# 56. Re-key stego carrier (PNG, WAV, BMP, or ASCII armor)
svault rotate -i carrier.png -o rotated.png -p "old-pass" -n "new-pass"
svault rotate -i carrier.asc -o rotated.asc -p "old-pass" -n "new-pass"

# 57. Re-key with DPAPI hardware toggle and policy clearing
svault rotate -i vault.svault -o dpapi_vault.svault -p "old-pass" -n "new-pass" --dpapi
svault rotate -i locked.svault -o unlocked.svault -p "old-pass" -n "new-pass" --clear-policy --json

# 58. Initialize detached integrity canary manifest for target directory
svault canary init -d ./vaults
svault canary init -d ./vaults -p "canary-auth-secret" --json

# 59. Verify canary integrity against on-disk files
svault canary verify -d ./vaults
svault canary verify -d ./vaults -p "canary-auth-secret" --strict --json

# 60. Launch interactive in-memory key-value vault shell
svault repl -v myvault.svault -p "session-pass"

# 61. Execute batch REPL commands non-interactively via --exec
svault repl -v myvault.svault -p "session-pass" --exec "set api_key sk_live_xyz --tag prod; set db_pass secret; save"

# 62. Query a secret directly with auto-expiring clipboard protection
svault repl -v myvault.svault -p "session-pass" --exec "get api_key --clip --clip-ttl 15"

# 63. Open REPL in read-only mode or export key-value entries to JSON
svault repl -v myvault.svault -p "session-pass" --readonly --exec "list" --json
svault repl -v myvault.svault -p "session-pass" --exec "export ./backup.json; exit"

# 64. Inspect host platform hardware token capabilities (Windows Hello, WebAuthn API, USB HID)
svault fido2 status
svault fido2 status --json

# 65. Enroll FIDO2 USB key or Windows Hello credential
svault fido2 enroll yubikey-5c --type usb --user alice --output ./yubikey.json
svault fido2 enroll hello-tpm --type hello --pin 849201 --json

# 66. Test authenticator assertion and verify PRF derivation fingerprint
svault fido2 test ./yubikey.json
svault fido2 test ./yubikey.json --json

# 67. Encrypt container with FIDO2 hardware credential binding + passphrase
svault encrypt -i secret.txt -o sealed.svault --fido2-cred ./yubikey.json -p "master-pass"

# 68. Decrypt container using enrolled hardware credential
svault decrypt -i sealed.svault -o restored.txt --fido2-cred ./yubikey.json -p "master-pass"

# 69. Multi-factor 2FA: Keyfile + FIDO2 physical token without passphrase
svault encrypt -i secret.txt -o mfa.svault -k usb_token.key --fido2-cred ./yubikey.json
svault decrypt -i mfa.svault -o restored.txt -k usb_token.key --fido2-cred ./yubikey.json

# 70. Re-key existing container to bind or unbind FIDO2 hardware credentials
svault rotate -i sealed.svault --in-place -p "old-pass" -n "new-pass" --fido2 --fido2-cred ./yubikey.json
svault rotate -i sealed.svault --in-place -p "new-pass" -n "plain-pass" --no-fido2 --fido2-cred ./yubikey.json

# 71. Generate a post-quantum hybrid keypair (X25519 + ML-KEM-768)
svault kem keygen -p recipient.pub -s recipient.key
svault kem keygen -p recipient.pub -s recipient.key --json

# 72. Seal a confidential file to a recipient public key (raw binary or ASCII armored)
svault kem seal -i classified.txt -o sealed.svault.pq -k recipient.pub
svault kem seal -i classified.txt -o sealed.asc -k recipient.pub --armor --json

# 73. Inspect post-quantum container metadata (ephemeral key, ML-KEM ciphertext size, CRC-32)
svault kem inspect -i sealed.svault.pq
svault kem inspect -i sealed.asc --json

# 74. Open and decrypt post-quantum sealed vault using recipient private key
svault kem open -i sealed.svault.pq -o restored.txt -k recipient.key
svault kem open -i sealed.asc -o restored.txt -k recipient.key --json
```

### License & Attribution

Copyright 2026 **GHSFS** ([https://github.com/GHSFS](https://github.com/GHSFS)).

Licensed under the **Apache License, Version 2.0** ([`LICENSE`](./LICENSE)).
Pursuant to Section 4(d) of the Apache License 2.0, any redistribution or derivative work in Source or Object form must retain the attribution notices in [`NOTICE`](./NOTICE).
