# shadow-vault (`svault`)

> Zero-trust steganography and dual-layer hardware-bound encrypted vault — conceal sensitive files inside ordinary PNG/audio carriers, seal them with Argon2id + ChaCha20-Poly1305 + Windows DPAPI, or embed dual-password plausible deniability decoy vaults.

[![Build](https://github.com/GHSFS/shadow-vault/actions/workflows/build.yml/badge.svg)](https://github.com/GHSFS/shadow-vault/actions/workflows/build.yml)
[![Tests](https://github.com/GHSFS/shadow-vault/actions/workflows/test.yml/badge.svg)](https://github.com/GHSFS/shadow-vault/actions/workflows/test.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](./LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20x64-0078D6)](#installation)

[English](#english) · [한국어](#한국어)

---

## English

### Overview

`shadow-vault` (`svault.exe`) is a single-binary cryptographic vault and steganography toolkit written in Rust. It is built for operators who need robust protection for high-value files (seed phrases, private keys, credentials, research notes):

1. **Dual-Layer Authenticated Encryption (`SVLT` v1/v2)** — combines memory-hard **Argon2id** key derivation + **ChaCha20-Poly1305** AEAD with optional **Windows DPAPI (`CryptProtectData`)** machine/user-session binding. Even if an attacker steals both your `.svault` file and your passphrase, a DPAPI-bound vault cannot be decrypted outside your Windows user account.
2. **Plausible Deniability & Decoy Vaults (`src/decoy.rs`)** — embeds both a primary hidden secret (unlocked with the master passphrase) and a harmless decoy payload (unlocked with the decoy passphrase) within a single container. Under coercion, revealing the decoy passphrase unlocks only the decoy payload, while the primary hidden slot remains statistically indistinguishable from uniform random noise (CSPRNG padding and ChaCha20-Poly1305 ciphertext).
3. **Lossless Carrier Steganography** — embeds encrypted containers inside ordinary media files:
   - **PNG Images** — injects an `svLt` private ancillary chunk before `IEND` with valid IEEE 802.3 CRC-32 checksums.
   - **WAV Audio Files** — supports both RIFF/WAVE subchunk (`svLt`) and 16-bit PCM audio sample Least Significant Bit (LSB) replacement with CRC-32 validation.
   - **BMP Images (`src/bmp.rs`)** — modulates least significant bits (LSB) across 24-bit uncompressed RGB pixel channels with strict 4-byte row padding preservation and 12-byte tamper-resistant stego envelope (`svLt` magic, length, payload, CRC-32).
4. **Universal Carrier Capacity Estimation (`capacity`)** — calculates total and usable byte capacity across steganography carrier files (`.bmp`, `.wav`, `.png`) with optional JSON output (`svault capacity <carrier> [--json]`).
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
16. **Unified Structured JSON Output Mode (`--json`)** — outputs clean, machine-readable JSON across all subcommands (`encrypt`, `decrypt`, `encrypt-decoy`, `decrypt-decoy`, `embed`, `extract`, `embed-wav`, `extract-wav`, `embed-bmp`, `extract-bmp`, `armor`, `dearmor`, `repair`, `shred`, `split`, `combine`, `keyfile`, `totp`, `clip`, `guard`, `pack-dir`, `unpack-dir`, `inspect`, `audit`, `compare`, `keygen`, `rotate`, `canary`) with consistent status, operation metrics, payload sizes, and cryptographic fingerprints for shell pipelines and CI/CD automation.
17. **Container Re-Key & Passphrase Rotation (`rotate`, `src/rotate.rs`)** — re-encrypts `.svault` containers and stego carriers (PNG, BMP, WAV, ASCII armor) with fresh CSPRNG salt and nonce, new passphrases or keyfiles, optional Windows DPAPI hardware binding toggles (`--dpapi`/`--no-dpapi`), temporal policy preservation or stripping (`--clear-policy`), and crash-resilient atomic file replacement (`svault rotate`).
18. **Detached Integrity Manifest & Canary Verification (`canary`, `src/canary.rs`)** — generates and verifies signed SHA-256 tamper canaries across directory trees of vaults and carriers (`svault canary init` / `svault canary verify`). Features multi-carrier format detection, optional Argon2id + HMAC-SHA256 signature authentication, constant-time verification, missing/modified/untracked anomaly reports, and machine-readable JSON output.
19. **Proactive Zeroize Hardening** — wipes sensitive intermediate key derivation buffers, ChaCha20 keys, Shamir polynomials, TOTP secrets, archive payload buffers, clipboard UTF-16 buffers, and DPAPI plaintext from memory upon drop using the `zeroize` crate.

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
  - **Universal Command Binding**: `--keyfile` / `-k` supported across `encrypt`, `decrypt`, `embed`, `extract`, `embed-wav`, `extract-wav`, `embed-bmp`, `extract-bmp`, `pack-dir`, `unpack-dir`, and decoy vaults.
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

# 9. Estimate carrier capacity for steganography embedding (.bmp, .wav, or .png)
svault capacity landscape.bmp
svault capacity track.wav --json

# 10. Conceal secret inside a 24-bit BMP image via pixel LSB steganography
svault embed-bmp -c landscape.bmp -s classified.txt -o landscape-stego.bmp -p "primary-secret-pass"

# 11. Extract secret from BMP image directly to auto-expiring clipboard
svault extract-bmp -c landscape-stego.bmp -p "primary-secret-pass" --clip --clip-ttl 15

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

# 29. Pack into a stego carrier (PNG, WAV, BMP) or ASCII armor
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
```

### License & Attribution

Copyright 2026 **GHSFS** ([https://github.com/GHSFS](https://github.com/GHSFS)).

Licensed under the **Apache License, Version 2.0** ([`LICENSE`](./LICENSE)).
Pursuant to Section 4(d) of the Apache License 2.0, any redistribution or derivative work in Source or Object form must retain the attribution notices in [`NOTICE`](./NOTICE).

---

## 한국어

### 개요

`shadow-vault`(`svault.exe`)는 중요한 파일(시드 문구, 개인키, 자격증명, 보안 문서 등)을 이중으로 보호하고 일반 미디어 파일 내부에 은닉할 수 있는 Rust 기반 단일 바이너리 보안 금고 및 스테가노그래피 도구입니다.

1. **이중 계층 인증 암호화 (`SVLT` v1/v2)** — 메모리 하드 KDF인 **Argon2id** + **ChaCha20-Poly1305** AEAD 암호화에 더해, 선택적으로 **Windows DPAPI (`CryptProtectData`)** 하드웨어/사용자 세션 귀속을 결합합니다. `--dpapi` 옵션을 켜면 암호화된 파일과 비밀번호가 외부로 유출되더라도 **본인의 Windows 계정 세션이 아니면 복호화가 원천 불가능**합니다.
2. **그럴듯한 부인(Plausible Deniability) 및 미끼(Decoy) 금고 (`src/decoy.rs`)** — 단일 컨테이너 내부에 진짜 극비 데이터(기본 비밀번호로 해제)와 무해한 미끼 데이터(미끼 비밀번호로 해제)를 동시에 봉인합니다. 강압에 의해 비밀번호 제출을 요구받을 때 미끼 비밀번호를 알려주면 **미끼 데이터만 정상 복호화**되며, 배후의 은닉 슬롯은 암호학적 난수(CSPRNG 패딩 및 암호문)와 통계적으로 완벽히 구분되지 않아 존재 자체를 입증할 수 없습니다.
3. **무손실 미디어 스테가노그래피 은닉** — 암호화된 컨테이너를 다양한 일반 미디어 파일 내부에 완벽히 은닉합니다:
   - **PNG 이미지 (`embed` / `extract`)**: 비표준 렌더링에 영향을 주지 않는 `svLt` 청크 + IEEE 802.3 CRC-32 무결성 검증 (미끼 금고 직접 은닉 지원).
   - **WAV 오디오 (`embed-wav` / `extract-wav`)**: RIFF 서브청크 모드(`--mode chunk`) 및 16비트 PCM 오디오 LSB 모드(`--lsb`) 지원 + CRC-32 검증.
   - **BMP 이미지 (`embed-bmp` / `extract-bmp`)**: 24비트 무압축 BMP R/G/B 색상 채널 LSB(최하위 비트) 변조 은닉, 4바이트 행 패딩 완벽 보존 및 12바이트 무결성 봉투(`svLt` 매직, 길이, CRC-32) 탑재.
4. **범용 캐리어 용량 측정기 (`capacity`)** — `.bmp`, `.wav`, `.png` 미디어 파일의 총 캐리어 크기, 실제 은닉 가용 바이트 용량, 스테고 오버헤드를 정밀 산출합니다 (`svault capacity <캐리어> [--json]`).
5. **샤미르 비밀 공유 (`M-of-N` 키 분할, `src/shamir.rs`)** — $\text{GF}(256)$ 유한체 기반 정보이론적 비밀 분할/복원 엔진. 분기 없는 상수시간(Constant-Time) 연산으로 부채널 공격을 방어하며, 마스터 복구 키, 비밀번호, 대용량 바이너리 금고를 $N$개 조각으로 분할하여 임의의 $M$개 조각으로만 원본을 복원(`svault split` / `svault combine`)합니다. 아머드 텍스트, 한 줄 압축, JSON 직렬화 및 SHA-256/CRC-32 무결성 검증을 지원합니다.
6. **비밀번호 강도 & 스테가노그래피 캐리어 엔트로피 감사기 (`src/audit.rs`)** — 섀넌 엔트로피(Shannon entropy bits/byte), 문자 풀 다양성, 취약 패턴 탐지(반복 문자, 연속 시퀀스, 키보드 워크, 리트스피크 사전 매칭)를 통해 비밀번호 내구성을 감사하고, PNG 청크·WAV 서브청크/LSB 스트림·BMP 픽셀 LSB 및 `.svault` 컨테이너의 변조·이상 징후를 정밀 분석(`svault audit <대상>` / `svault audit -p <비밀번호>`)합니다.
7. **RFC 6238 TOTP 2FA 보안 금고 (`src/totp.rs`)** — 외부 라이브러리 의존성 0개의 독립 로컬 암호화 2차 인증(2FA) 금고 엔진. RFC 4648 Base32 코덱, 자체 완비 RFC 3174 SHA-1, RFC 2104 HMAC (SHA-1/256/512), `otpauth://totp/...` URI 파서/직렬화기, 부채널 타이밍 공격을 방어하는 상수시간 검증 및 터미널 시각적 잔여시간 카운트다운 진행바를 지원합니다 (`svault totp add`, `svault totp code`, `svault totp list`, `svault totp verify`).
8. **자동 만료 클립보드 가드 (`src/clipboard_guard.rs`)** — 복호화된 비밀번호, TOTP 2FA 코드, 복구 시드문구를 Windows 클립보드로 안전하게 복사하고 설정된 유효시간(TTL, 예: `--clip-ttl 15`) 후 자동 소거합니다. Windows 10/11 클립보드 기록(Win + V) 및 클라우드 동기화 등록을 원천 차단하는 포맷 메타데이터(`CanIncludeInClipboardHistory`, `ExcludeClipboardContentFromMonitorProcessing`)를 자동 주입하며, 소거 전 SHA-256 상수시간 지문 비교(`constant_time_eq_32`)를 수행해 사용자가 이후에 복사한 다른 클립보드 데이터를 덮어쓰지 않도록 안전하게 보호합니다 (`svault clip`, 및 복호화 명령 시 `--clip`).
9. **리드-솔로몬 / 패리티 오류 정정 아머 (`src/armor.rs`)** — 블록 패리티 복구 스트라이프와 ASCII 아머드 `.svault.asc` 내보내기/가져오기/복구를 지원하여 부분적인 비트 손상(Bit Rot)이나 텍스트 전송 채널 상의 손상에서도 컨테이너를 복원합니다. $\text{GF}(256)$ 상의 코시(Cauchy) 생성 행렬 $[I_K; A]$을 사용하여 MDS(최대 거리 분리) 부호 성질을 보장하므로, 총 $K + M$개 스트라이프 중 임의의 $K$개 온전한 조각만 있으면 모든 원본 데이터를 완벽하게 재구성합니다. 자동 손상 탐지, 자가 치유 복구(`svault repair`), `inspect` 및 `audit` 자동 감지, 자동 만료 클립보드 가드를 결합 지원합니다 (`svault armor`, `svault dearmor`, `svault repair`).
10. **디렉터리 및 다중 파일 매니페스트 패킹 (`src/archive.rs`)** — 전체 디렉터리 트리를 상대 경로 정규화, 다중 계층 Zip Slip / 경로 순회(Path Traversal) 방어, 압축 폭탄(Zip Bomb) 방어, 파일별 SHA-256 암호학적 매니페스트, Unix/Windows 파일 권한 보존과 함께 단일 `SVLT` 컨테이너로 완전 밀봉(`svault pack-dir` / `svault unpack-dir`)합니다. `--list`, `--verify-only`, `--overwrite`, `--json`, `--dpapi` 및 투명한 스테가노그래피(PNG/WAV/BMP) & ASCII 아머 캐리어 추출을 지원합니다.
11. **키파일 + 비밀번호 이중 인증(2FA) 키 유도 (`src/keyfile.rs`)** — 외장 하드웨어 또는 USB 키파일(`--keyfile <경로>`)을 사용자 비밀번호와 결합하여 64 KiB 스트리밍 HMAC-SHA256 사전 해싱 후 Argon2id로 키를 유도합니다. 비밀번호 + 키파일 이중 인증(2FA) 및 키파일 단독 모드를 모두 지원하며, 내장 CSPRNG 키파일 생성(`svault keyfile generate`), SHA-256 지문 출력(`svault keyfile fingerprint`), 섀넌 엔트로피 감사(`svault keyfile inspect`), 제로화 메모리 소거 및 모든 미디어 스테가노그래피 캐리어·디렉터리 패킹과의 투명한 통합을 지원합니다.
12. **청크 스트리밍 암호화 엔진 (`src/stream.rs`)** — 멀티 기가바이트(Multi-GB) 대용량 파일과 데이터 스트림을 $O(1)$ 고정 RAM 슬라이딩 윈도우로 안전하게 암호화 및 복호화합니다 (기본 4 MiB 청크, 64 KiB–64 MiB 범위). `SVST` v1 바이너리 헤더, 청크별 고유 논스 유도(`SHA256(b"shadow-vault:stream-chunk-nonce:v1" || base_nonce || chunk_index || tag)`), 청크별 AAD 위변조 방어, 시간 잠금/만료 정책 결합 및 Windows DPAPI 스트림 키 하드웨어 귀속을 지원합니다 (`svault stream encrypt`, `svault stream decrypt`, `svault stream inspect`, `--stream`, `--chunk-size`).
13. **스테가노그래피 캐리어 시각/통계적 디프 리포트 (`src/diff.rs`)** — 원본과 스테가노그래피 캐리어 간의 시각 신호 왜곡(MSE, PSNR, MAE, 순수 LSB 변조율), 16비트 오디오 왜곡(SNR, PSNR), 구조적 청크 테이블 정렬 및 섀넌 엔트로피 차이를 비교 분석(`svault compare`)합니다.
14. **데드맨 스위치 & 최대 실패 횟수 자동 파기 가드 (`src/guard.rs`)** — 변조 방지 시도 원장(`.guard` 동반 파일 또는 은닉 전역 원장)을 기반으로 $K$회 연속 인증 실패 시 3단계(0x00, 0xFF, CSPRNG) 영구 파일 파쇄를 자동 실행하며, 비활동 기한 만료 시 셀프 파쇄를 발동하는 데드맨 스위치를 제공합니다 (`svault guard arm`, `svault guard status`, `svault guard checkin`, `svault guard reset`, `svault guard trigger`).
15. **결정론적 & CSPRNG 비밀번호 생성기 (`src/passgen/`)** — 2,048개 BIP-39 단어 사전 기반 다이스웨어(Diceware) 복구 문구 생성, 시각적 혼동 문자 제거(`--exclude-ambiguous`) 패스워드/PIN 생성, Hex/Base64/Base32 원시 암호학적 바이트 토큰 생성, 마스터 시드 결정론적 유도(`--seed`, `--context`), 5단계 엔트로피 내구성 평가 및 자동 만료 클립보드 가드 결합을 지원합니다 (`svault keygen`).
16. **전 서브커맨드 전수 구조화 JSON 출력 모드 (`--json`)** — 모든 서브커맨드(`encrypt`, `decrypt`, `encrypt-decoy`, `decrypt-decoy`, `embed`, `extract`, `embed-wav`, `extract-wav`, `embed-bmp`, `extract-bmp`, `armor`, `dearmor`, `repair`, `shred`, `split`, `combine`, `keyfile`, `totp`, `clip`, `guard`, `pack-dir`, `unpack-dir`, `inspect`, `audit`, `compare`, `keygen`, `rotate`, `canary`)에서 기계 판독 가능한 일관된 표준 JSON 응답(`status`, `command`, 세부 메타데이터, 바이트 크기, 지문)을 제공하여 CI/CD 및 자동화 쉘 스크립트 파이프라인 연계를 지원합니다.
17. **컨테이너 키 교체 및 비밀번호 회전 (`rotate`, `src/rotate.rs`)** — 기존 `.svault` 컨테이너 또는 스테가노그래피 캐리어(PNG, BMP, WAV, ASCII 아머)를 새로운 비밀번호나 키파일로 재암호화(`svault rotate`)합니다. 매 회전마다 독립적인 16바이트 솔트와 12바이트 논스를 생성하고, Windows DPAPI 하드웨어 귀속 설정 변경(`--dpapi`/`--no-dpapi`), 시간 잠금/만료 정책 보존 또는 제거(`--clear-policy`), 원자적 임시 파일 치환을 지원합니다.
18. **분리형 무결성 매니페스트 및 카나리 검증 (`canary`, `src/canary.rs`)** — 볼트 및 스테가노그래피 캐리어 디렉터리의 변조 여부를 모니터링하는 서명된 SHA-256 카나리 매니페스트를 생성하고 검증(`svault canary init` / `svault canary verify`)합니다. 다중 캐리어 포맷 자동 식별, Argon2id + HMAC-SHA256 서명 인증, 상수 시간 서명 검증, 수정/삭제/미추적 이상 탐지 및 구조화 JSON 출력을 지원합니다.
19. **선제적 메모리 제로화 보호 (`zeroize`)** — Argon2id 유도 키, ChaCha20 키 버퍼, 샤미르 다항식 계수, TOTP 비밀키, 아카이브 페이로드 버퍼, 클립보드 UTF-16 중간 버퍼 및 Windows DPAPI 복호화 평문 버퍼를 스코프 종료 즉시 메모리에서 0x00으로 완전 소거합니다.

### 주요 기능

- **Argon2id + ChaCha20-Poly1305 AEAD** — 매 암호화마다 새로운 128비트 솔트와 96비트 논스를 생성하며 변조 시 즉시 복호화를 거부합니다.
- **자동 만료 클립보드 가드 (`clip`)** — 안전한 자격증명 복사 및 자동 파기 엔진:
  - **네이티브 Win32 API 직통 제어**: 외장 크레이트 없이 Windows 클립보드 API(`OpenClipboard`, `EmptyClipboard`, `SetClipboardData`, `CloseClipboard`)를 10회 재시도 백오프로 안정적으로 제어.
  - **클립보드 기록 및 클라우드 동기화 영구 차단**: Windows 10/11 전용 포맷(`CanIncludeInClipboardHistory`, `ExcludeClipboardContentFromMonitorProcessing`, `Clipboard Viewer Ignore`)을 자동 등록/주입하여 Win+V 히스토리 잔존 및 클라우드 유출을 원천 방어.
  - **상수시간 지문 일치 검증**: 소거 시점에 클립보드 내용의 SHA-256 다이제스트를 상수시간(`constant_time_eq_32`)으로 비교하여, 보호 중인 비밀값일 때만 정확히 소거하고 이후 사용자가 복사한 일반 데이터는 덮어쓰지 않고 보존.
  - **시각적 카운트다운 진행바 & 즉시 소거**: 실시간 터미널 진행바(`[████████░░] 12s`), 비차단 엔터 키 입력 시 즉시 소거, 백그라운드 데몬 및 무음 모드(`--silent`) 지원.
  - **주요 명령어 직통 연동**: `decrypt`, `decrypt-decoy`, `extract`, `extract-wav`, `totp code` 등 모든 자격증명 출력 명령에 `--clip` 및 `--clip-ttl <초>` 옵션 완전 결합.
- **RFC 6238 TOTP 2FA 보안 금고 (`totp`)** — 암호화 다중 계정 2단계 인증 엔진:
  - **외부 의존성 제로**: 자체 Base32 코덱(RFC 4648), RFC 3174 SHA-1, RFC 2104 HMAC (SHA-1, SHA-256, SHA-512) 완비 및 RFC 4226 부록 D, RFC 6238 부록 B 테스트 벡터 100% 통과.
  - **하드웨어 귀속 & AEAD 봉인**: 계정 자격증명을 Argon2id + ChaCha20-Poly1305 및 Windows DPAPI로 이중 암호화된 `.svault` 컨테이너에 안전 저장.
  - **표준 Key URI 호환성**: `otpauth://totp/[Issuer:]Account?...` URI 완벽 파싱 및 직렬화 지원.
  - **상수시간 타이밍 공격 방어**: 타이밍 사이드채널 방어 비교(`constant_time_eq`) 및 설정 가능한 시간 오차 허용 윈도우($\pm S$).
  - **터미널 UX & 시각적 게이지**: 컬러 터미널 코드 출력, 잔여 초수 시각적 프로그레스 바 (`[████████░░] 19s`), 파이프라인 연동용 `--json` 모드.
- **비밀번호 강도 & 캐리어 엔트로피 감사 (`audit`)**:
  - **섀넌 및 풀 엔트로피 계산**: 바이트당 섀넌 엔트로피($0.0 \le H \le 8.0$), 유효 엔트로피 및 문자 풀 공간($L \log_2 R$) 정밀 측정.
  - **취약 패턴 탐지**: 연속된 문자(`1234`, `abcd`), 반복 문자(`aaaa`), QWERTY 키보드 워크(`qwerty`, `asdfgh`), 리트스피크 변형 사전 매칭(`p@ssw0rd`).
  - **다중 공격 모델 크랙 소요시간 예측**: 온라인 요청 제한(100회/초), 오프라인 Argon2id(1,000회/초), 오프라인 고속 GPU 해시 클러스터(100억회/초).
  - **스테가노그래피 캐리어 정밀 분석**: PNG 청크 무결성, `IEND` 이후 미인가 트레일링 데이터(EOF 인젝션), WAV RIFF 서브청크 및 16비트 PCM LSB 스트림 매직 검증, 카이제곱($\chi^2$) 난수성 검정.
  - **구조화 JSON 출력 (`--json`)**: CI/CD 및 자동화 보안 점검 파이프라인 연동 지원.
- **샤미르 비밀 공유 ($M$-of-$N$ 키 분할)** — $\text{GF}(256)$ 상에서 $2 \le M \le N \le 255$ 임계값 비밀 분할:
  - **상수시간 유한체 연산**: 비밀 의존 분기 및 룩업 테이블이 없는 branchless peasant 곱셈 및 페르마 소정리 역원($a^{-1} = a^{254}$).
  - **이중 계층 무결성 보호**: 복원 후 SHA-256 해시 검증으로 변조 조각 결합 원천 차단 및 조각별 CRC-32 체크섬 검증.
  - **다양한 직렬화 규격**: ASCII 아머드 블록(`-----BEGIN SHADOW VAULT SHARE-----`), 컴팩트 단일 라인(`SVLT-S1-...`), 구조화 JSON 지원.
- **그럴듯한 부인 이중 암호 컨테이너** — 진짜 비밀과 미끼 데이터를 단일 컨테이너에 공존 보관:
  - **자동 슬롯 식별**: `svault decrypt -p <비밀번호>` 입력 시 입력된 비밀번호에 맞춰 미끼 또는 주 슬롯을 자동 감지하여 복호화합니다.
  - **통계적 비식별 은닉 슬롯**: 은닉 슬롯에는 평문 헤더나 길이 필드가 전혀 없어 미끼 키 소유자에게 샤논 엔트로피 ~8.0 bits/byte의 균일 난수 패딩으로 인식됩니다.
  - **크기 난독화 패딩 (`--padding <바이트>`)**: 고정된 256바이트 정렬 및 임의 크기 난수 패딩을 주입하여 파일 크기 분석을 무력화합니다.
- **Windows DPAPI 이중 잠금 (`--dpapi`)** — 생성한 Windows 사용자 프로필에 암호문을 하드웨어/세션 단위로 귀속시킵니다.
- **선제적 메모리 제로화 (`zeroize`)** — 민감한 키 버퍼와 평문 메모리를 스코프 종료 시 즉각 안전하게 소거합니다.
- **PNG 이미지 은닉 (`embed` / `extract`)** — PNG 표준 청크 규격과 CRC-32 체크섬을 준수하여 이미지 손상 없이 암호화 페이로드 및 미끼 컨테이너를 은닉·추출합니다.
- **WAV 오디오 은닉 (`embed-wav` / `extract-wav`)** — RIFF 서브청크 은닉 및 16비트 PCM LSB 미세 비트 은닉(음질/재생 영향 제로, 파일 크기 보존)을 지원하며 자동 감지 추출(`--mode auto`)을 지원합니다.
- **BMP 24비트 픽셀 LSB 스테가노그래피 (`embed-bmp` / `extract-bmp`)** — 24비트 무압축 BMP 이미지 비트 단위 은닉:
  - **행 패딩 완벽 보존**: 표준 Windows BMP 4바이트 행 패딩(Row Stride Padding)을 변조하지 않고 R, G, B 색상 채널만 정확히 순회하여 이미지 뷰어 왜곡 및 파일 손상 원천 차단.
  - **12바이트 무결성 봉투**: `[매직 "svLt": 4B][길이: 4B LE][페이로드: NB][CRC-32: 4B LE]` 봉투 캡슐화 및 부채널 저항 상수시간 CRC-32 검증.
  - **캐리어 감사 & 스테그분석 (`audit`)**: `svault audit` 명령어로 BMP 픽셀 LSB 무결성, 은닉 스트림 유무 및 정상 이미지 판별.
  - **미끼 금고 및 클립보드 연동**: 그럴듯한 부인 이중 암호 미끼 금고(`--decoy`, `--decoy-passphrase`) 및 자동 만료 클립보드(`--clip`, `--clip-ttl`) 완전 지원.
- **리드-솔로몬 / 패리티 오류 정정 아머 (`armor` / `dearmor` / `repair`)** — 강력한 컨테이너 오류 정정 및 ASCII 아머드 엔진:
  - **$\text{GF}(256)$ 코시 MDS 리드-솔로몬 부호**: 코시 원소 $A_{i, j} = \frac{1}{(K + i) \oplus j}$를 적용한 $[I_K; A]$ 생성 행렬 기반. $\text{GF}(256)$ 가우스 소거법을 통해 $K + M$개 스트라이프 중 임의의 $K$개 온전한 조각만으로 모든 데이터 스트라이프를 완벽 복원.
  - **스트라이프별 CRC-32 및 전체 SHA-256 바인딩**: 개별 스트라이프마다 독립적인 CRC-32 검증을 수행하여 손상 위치를 정밀 격리하고, 전체 컨테이너 복원 후 SHA-256 다이제스트로 최종 무결성 입증.
  - **자가 치유 복구 명령 (`repair`)**: 손상된 스트라이프를 재구성하여 완전히 깨끗한 새 `.svault.asc` 문서를 재출력하거나 바이너리로 직통 추출(`--binary`)하며 상세 `--json` 진단 보고서 제공.
  - **`dearmor` 시 투명한 자동 복원**: 복호화/해제 과정에서 데이터 스트라이프 손상이 감지되면 별도 복구 명령 없이도 코시 RS 소거 복원을 전자동 실행하여 원본 복원.
  - **`inspect` 및 `audit` 자동 감지 연동**: 아머드 컨테이너의 스트라이프 구성 상태 및 CRC-32 무결성을 즉시 검사.
- **디렉터리 및 다중 파일 매니페스트 패킹 (`pack-dir` / `unpack-dir`)** — 보안 강화된 단일 봉인 디렉터리 아카이브:
  - **`SVAR` v1 바이너리 규격**: 18바이트 헤더(`SVAR` v1), 엔트리별 메타데이터, 개별 SHA-256 다이제스트, 8바이트 트레일러(`SVEN` 매직 및 CRC-32 체크섬).
  - **경로 순회 & Zip Slip 원천 차단**: `/` 기반 상대 경로 정규화, `..`, 절대/UNC 경로, 드라이브 문자, 콜론 대체 데이터 스트림(ADS), 널 바이트 및 Windows 예약 장치명(`CON`, `PRN`, `AUX`, `NUL`, `COM1..9`, `LPT1..9`) 완벽 차단.
  - **압축 폭탄 방어**: 총 아카이브 크기(8 GiB), 단일 파일 크기(4 GiB), 엔트리 수(100,000개), 경로 길이(4,096바이트), 디렉터리 깊이(64단계) 상한 및 메모리 할당 전 슬라이스 길이 선제 검증.
  - **유연한 매니페스트 CLI**: `--list`로 아카이브 내용 조회, `--verify-only`로 디스크 기록 없이 메모리 상에서 파일별 SHA-256 무결성 즉시 검증, `--overwrite`로 대상 파일 덮어쓰기 안전 제어.
  - **투명한 캐리어 & 아머 자동 해제**: `unpack-dir` 실행 시 `.svault.asc` 아머드 문서 및 PNG/WAV/BMP 스테가노그래피 캐리어로부터 컨테이너를 전자동 추출.
- **범용 캐리어 용량 측정 (`capacity`)** — `.bmp`, `.wav`, `.png` 미디어의 전체 바이트, 순수 은닉 가용 용량, 12바이트 스테고 봉투 오버헤드를 정밀 계산하며 파이프라인 연동용 `--json` 출력 지원.
- **컨테이너 헤더 검사 (`inspect`)** — 복호화 없이 `.svault`, `.png`, `.wav`, `.bmp` 파일의 컨테이너 버전, DPAPI 귀속 여부, 미끼 컨테이너 여부, 페이로드 크기, 솔트 값을 즉시 확인합니다 (은닉 슬롯의 크기는 은폐).
- **시간 잠금 및 자동 만료 정책 헤더 (`policy`)** — 암호화 컨테이너에 시간 기반 접근 제어 정책을 암호학적으로 바인딩:
  - **인증된 정책 헤더 (`SVPO`)**: 매직 `SVPO`, 버전 1, 플래그(`HAS_NOT_BEFORE`, `HAS_EXPIRES_AT`, `HAS_DESCRIPTION`), `created_at`, `not_before`, `expires_at`, 임의 설명(최대 256B) 및 CRC-32 무결성 검증을 포함하는 표준 28바이트 바이너리 헤더.
  - **AEAD 연관 데이터(AAD) 완벽 결속**: 직렬화된 정책 헤더 전체가 ChaCha20-Poly1305의 추가 인증 데이터(`aad`)로 주입되어, 타임스탬프나 설명이 단 1비트라도 변조되면 Poly1305 MAC 검증 실패로 복호화가 원천 차단됩니다.
  - **시점 기반 접근 제어**: `--not-before`로 지정된 시점 이전에는 `TimeLocked` 에러로 복호화가 거부되며, `--expires-at` 또는 `--expires-in`으로 설정된 수명이 만료되면 `Expired` 에러로 즉시 무효화됩니다.
  - **유연한 시간 표기법**: 유닉스 타임스탬프(`1791850000`), ISO-8601 UTC 날짜/일시(`2026-10-15T00:00:00Z`, `2026-12-31`), 상대 기간(`+1h`, `+7d`, `+30m`, `+1y`)을 자유롭게 지원.
  - **검사 및 감사 연동**: `inspect` 명령어로 활성 여부(`ACTIVE`, `TIMELOCKED`, `EXPIRED`), 잔여/초과 시간, UTC 일시 및 설명을 확인 가능하며(`--json` 지원), `audit` 명령어가 정책 헤더 오프셋을 자동 감지하여 엔트로피를 정밀 분석합니다.
- **키파일 + 비밀번호 이중 인증(2FA) 키 유도 (`keyfile`)** — 외장 물리 USB 토큰이나 키파일을 컨테이너 암호화에 결속:
  - **64 KiB 스트리밍 HMAC-SHA256**: 임의 크기(16바이트 ~ 수십 메가바이트)의 키파일을 64 KiB 고정 메모리 버퍼로 스트리밍 처리하며 즉시 제로화.
  - **암호학적 2FA 및 키파일 단독 모드**: 비밀번호 + 키파일 결합 시 `HMAC-SHA256(key = 비밀번호, data = "shadow-vault:keyfile-v1:" || 키파일_스트림)`으로 256비트 시드를 유도하며, 키파일 단독 모드 시 도메인 구분자 `b"shadow-vault:keyfile-only:v1"`을 적용해 Argon2id로 전달.
  - **CSPRNG 키파일 생성기 (`svault keyfile generate`)**: `rand::rngs::OsRng` 기반의 고품질 난수 키파일(기본 64바이트) 안전 생성.
  - **지문 및 섀넌 엔트로피 검사 (`inspect` / `fingerprint`)**: SHA-256 지문(`SHA256:<hex>`) 및 표본 크기 정규화가 적용된 섀넌 엔트로피 품질 평가 제공.
  - **전 명령어 유니버설 연동**: `encrypt`, `decrypt`, `embed`, `extract`, `embed-wav`, `extract-wav`, `embed-bmp`, `extract-bmp`, `pack-dir`, `unpack-dir`, 디코이 금고 등 전체 암호화 워크플로우에 `--keyfile` / `-k` 완전 결합.
- **청크 스트리밍 암호화 (`stream`)** — 고정 $O(1)$ 메모리 대용량 스트리밍 인증 암호화:
  - **`SVST` v1 바이너리 와이어 포맷**: 38바이트 베이스 헤더(`SVST`, 버전 1, 플래그, 청크 크기, 솔트, 베이스 논스)와 선택적 `SVPO` 정책 헤더 및 DPAPI 암호화 스트림 키 탑재.
  - **청크 논스 및 AAD 암호학적 결합**: 청크마다 고유 논스를 유도하여 IV 재사용을 방지하고, AAD에 청크 인덱스, 태그(중간/종료), 솔트, 정책 해시를 바인딩하여 순서 변경, 누락, 주입 공격을 원천 방어.
  - **전체 파일 메모리 적재 제로(Zero)**: 2개 버퍼 슬라이딩 윈도우로 0바이트부터 수십 기가바이트 파일까지 메모리 고갈 없이 고속 처리.
  - **투명한 자동 감지**: `svault decrypt` 및 `svault inspect`가 스트리밍 컨테이너를 자동 인식하여 스트리밍 엔진으로 즉시 분기.
- **대화형 인메모리 금고 셸 (`repl` / `shell`)** — 단 한 번의 복호화로 키-값 비밀 저장소를 메모리에 적재하여 디스크 평문 저장 없이 안전하게 조회, 추가, 삭제, 내보내기, 가져오기를 수행하는 대화형 REPL 셸: 자동 소거 클립보드 보호(`--clip`), 읽기 전용 감사 모드(`--readonly`), 비대화형 배치 실행(`--exec`), 무중단 원자적 재암호화 저장 지원.
- **다중 패스 완전 파쇄 (`shred`)** — 원본 평문 파일을 삭제할 때 `0x00` ➔ `0xFF` ➔ 난수 덮어쓰기 후 디스크 동기화 및 길이 0 절삭을 수행해 포렌식 복구를 차단합니다.

### 사용법 요약

```bash
# 1. 파일 암호화 (비밀번호 + Windows DPAPI 이중 잠금)
svault encrypt -i secret.txt -o secret.svault -p "비밀번호" --dpapi

# 2. 극비 파일과 미끼 파일을 단일 컨테이너에 은닉 암호화 (그럴듯한 부인)
svault encrypt -i secret.txt --decoy harmless.txt -o deniable.svault \
  -p "주-비밀번호" --decoy-passphrase "미끼-비밀번호" --padding 512

# 3. 미끼 비밀번호로 복호화 (미끼 파일만 노출)
svault decrypt -i deniable.svault -o decoy_out.txt -p "미끼-비밀번호"
# 주 비밀번호로 복호화 (진짜 극비 파일 복원)
svault decrypt -i deniable.svault -o secret_out.txt -p "주-비밀번호"

# 4. 평범한 PNG 이미지 속에 비밀/미끼 금고 암호화 은닉
svault embed -c photo.png -s secret.txt --decoy harmless.txt -o photo_hidden.png \
  -p "주-비밀번호" --decoy-passphrase "미끼-비밀번호"

# 5. PNG 이미지에서 비밀 파일 추출 및 복호화
svault extract -c photo_hidden.png -o recovered.txt -p "주-비밀번호"
svault extract -c photo_hidden.png -o harmless_rec.txt --decoy-passphrase "미끼-비밀번호"

# 6. WAV 오디오 파일 속에 비밀 파일 암호화 은닉 (서브청크 또는 16비트 PCM LSB)
svault embed-wav -c audio.wav -s secret.txt -o audio_lsb.wav -p "비밀번호" --lsb

# 7. WAV 오디오 파일에서 비밀 파일 추출 및 복호화
svault extract-wav -c audio_lsb.wav -o recovered_audio.txt -p "비밀번호"

# 8. 스테가노그래피 캐리어 용량 측정 (.bmp, .wav, .png)
svault capacity photo.bmp
svault capacity audio.wav --json

# 9. 24비트 BMP 이미지 속에 비밀 파일 픽셀 LSB 암호화 은닉
svault embed-bmp -c photo.bmp -s secret.txt -o photo_lsb.bmp -p "비밀번호"

# 10. BMP 이미지에서 비밀 파일 추출 후 안전 클립보드로 직접 복사 (15초 후 자동 소거)
svault extract-bmp -c photo_lsb.bmp -p "비밀번호" --clip --clip-ttl 15

# 11. 컨테이너 또는 스테고 미디어(.png, .wav, .bmp) 메타데이터 조회
svault inspect photo_lsb.bmp

# 12. 원본 평문 파일 3-패스 완전 파쇄
svault shred secret.txt --passes 3

# 13. 마스터 복구 키 또는 비밀값을 3-of-5 샤미르 조각(Shamir Shares)으로 분할
svault split -s "마스터-복구-시드문구" -m 3 -n 5 -o shares/share

# 14. 임의의 3개 조각을 결합하여 원본 비밀값 완벽 복원
svault combine shares/share_1.share shares/share_3.share shares/share_5.share -o restored.txt

# 15. 비밀번호 강도, 섀넌 엔트로피 및 크랙 시간 정밀 감사
svault audit -p "안전한-비밀번호-문구-2026!"

# 16. 스테고 이미지/오디오 파일 또는 컨테이너 이상 징후 분석
svault audit photo_lsb.bmp --json

# 17. Base32 시크릿 또는 otpauth:// URI로 2FA 계정 등록
svault totp add github --secret "JBSWY3DPEHPK3PXP" --issuer "GitHub" --vault totp.svault -p "금고비밀번호"
svault totp add --uri "otpauth://totp/Google:alice?secret=JBSWY3DPEHPK3PXP&issuer=Google" --vault totp.svault -p "금고비밀번호"

# 18. 실시간 6자리 2FA 인증 코드 생성 (시각적 잔여시간 게이지 및 --json 지원)
svault totp code github --vault totp.svault -p "금고비밀번호"
svault totp code github --vault totp.svault -p "금고비밀번호" --json

# 19. 시간 오차 윈도우 기반 OTP 코드 검증 (+/- 1 스텝)
svault totp verify github 123456 --skew 1 --vault totp.svault -p "금고비밀번호"

# 20. 계정 목록 조회 및 otpauth:// URI 내보내기
svault totp list --vault totp.svault -p "금고비밀번호"
svault totp export github --vault totp.svault -p "금고비밀번호"

# 21. 15초 자동 만료 가드를 적용하여 비밀값을 클립보드에 안전 복사
svault clip copy "초특급-비밀번호" --ttl 15
svault clip copy "초특급-비밀번호" --ttl 15 --silent

# 22. 클립보드 메타데이터 상태 확인 및 수동 즉시 완전 소거
svault clip status
svault clip clear

# 23. 터미널 노출 및 디스크 평문 저장 없이 클립보드로 직통 복호화
svault decrypt -i secret.svault -p "금고비밀번호" --clip --clip-ttl 30
svault totp code github --vault totp.svault -p "금고비밀번호" --clip --clip-ttl 15

# 24. 코시 리드-솔로몬 패리티 스트라이프가 적용된 ASCII 아머드 파일(.svault.asc) 생성
svault armor -i secret.svault -o secret.svault.asc -k 4 -m 2

# 25. ASCII 아머드 파일을 원본 .svault 컨테이너로 복원
svault dearmor -i secret.svault.asc -o recovered.svault

# 26. 손상된 .svault.asc 파일 코시 리드-솔로몬 패리티로 자가 치유 복구
svault repair -i corrupted.svault.asc -o repaired.svault.asc --json
svault repair -i corrupted.svault.asc -o direct_recovered.svault --binary

# 27. 아머드 컨테이너 스트라이프 상태 검사 및 무결성 감사
svault inspect secret.svault.asc
svault audit secret.svault.asc --json

# 28. 전체 디렉터리 트리를 암호화된 .svault 아카이브로 패킹
svault pack-dir -i ./my_project -o project.svault -p "금고비밀번호" --list

# 29. 스테가노그래피 캐리어(PNG, WAV, BMP) 또는 ASCII 아머로 디렉터리 은닉 패킹
svault pack-dir -i ./my_project -o project.png -p "금고비밀번호" --carrier cover.png
svault pack-dir -i ./my_project -o project.svault.asc -p "금고비밀번호" --armor

# 30. 디렉터리 언패킹, 아카이브 내용 조회 및 무결성 다이제스트 사전 검증
svault unpack-dir -i project.svault -p "금고비밀번호" --list
svault unpack-dir -i project.svault -p "금고비밀번호" --verify-only
svault unpack-dir -i project.svault -o ./restored_project -p "금고비밀번호" --overwrite

# 31. 미래 지정 시점까지 복호화를 거부하는 에스크로 시간 잠금 금고 생성
svault encrypt -i escrow.txt -o escrow.svault -p "금고비밀번호" --not-before "2026-12-31T00:00:00Z" --policy-desc "연말 해제 에스크로"

# 32. 2시간 뒤 자동 만료되거나 특정 날짜에 만료되는 금고 생성
svault encrypt -i token.txt -o token.svault -p "금고비밀번호" --expires-in 2h --policy-desc "단기 세션 토큰"
svault encrypt -i doc.txt -o doc.svault -p "금고비밀번호" --expires-at "2026-10-15"

# 33. 복호화 없이 정책 헤더 및 만료 상태 점검 (터미널 텍스트 및 JSON)
svault inspect escrow.svault
svault inspect escrow.svault --json

# 34. 특정 기준 시점(--at-time)으로 복호화 시뮬레이션 및 검증
svault decrypt -i escrow.svault -o restored.txt -p "금고비밀번호" --at-time "2027-01-01"

# 35. 암호학적 난수 USB 키파일 생성 (CSPRNG, 기본 64바이트)
svault keyfile generate -o usb_token.key --bytes 64

# 36. 키파일 지문 및 섀넌 엔트로피 검사 (터미널 텍스트 및 JSON)
svault keyfile inspect usb_token.key
svault keyfile inspect usb_token.key --json
svault keyfile fingerprint usb_token.key

# 37. 비밀번호 + 키파일 이중 인증(2FA) 암호화 및 복호화
svault encrypt -i secret.txt -o sealed.svault -p "마스터비밀번호" -k usb_token.key
svault decrypt -i sealed.svault -o restored.txt -p "마스터비밀번호" -k usb_token.key

# 38. 비밀번호 입력 없는 키파일 단독 암호화
svault encrypt -i token.txt -o hardware.svault -k usb_token.key
svault decrypt -i hardware.svault -o restored.txt -k usb_token.key

# 39. 키파일 2FA를 적용한 디렉터리 아카이브 패킹 및 언패킹
svault pack-dir -i ./confidential -o archive.svault -p "패킹비밀번호" -k usb_token.key
svault unpack-dir -i archive.svault -o ./unpacked -p "패킹비밀번호" -k usb_token.key

# 40. 멀티 기가바이트 대용량 파일 청크 스트리밍 암호화 (기본 4 MiB 또는 사용자 지정 청크)
svault stream encrypt -i large_dataset.iso -o large_dataset.svault -p "스트리밍비밀번호"
svault encrypt -i database.backup -o db.svault -p "스트리밍비밀번호" --stream --chunk-size 8M

# 41. 스트리밍 컨테이너 복호화 (SVST 자동 감지 또는 전용 stream 서브커맨드)
svault decrypt -i large_dataset.svault -o restored.iso -p "스트리밍비밀번호"
svault stream decrypt -i db.svault -o restored_db.backup -p "스트리밍비밀번호"

# 42. 복호화 없이 스트리밍 컨테이너 메타데이터 검사 (텍스트 및 JSON)
svault stream inspect large_dataset.svault
svault inspect large_dataset.svault --json

# 43. 원본 캐리어와 스테고 캐리어 간 시각/음향 품질 및 바이트 엔트로피 대조
svault compare cover.bmp stego.bmp
svault compare cover.png stego.png --json
svault diff original.wav stego.wav --detailed

# 44. 3회 연속 암호 오입력 시 파일 영구 파쇄 및 7일 데드맨 스위치 가드 장착
svault encrypt -i secret.txt -o guarded.svault -p "금고비밀번호" --max-attempts 3 --dead-man 7d --guard-companion

# 45. 기존 스테고 캐리어 또는 볼트 파일에 가드 직접 무장
svault guard arm -t stego.png --max-attempts 3 --companion
svault guard arm -t vault.svault --max-attempts 5 --dead-man 24h

# 46. 가드 상태 및 잔여 시도 횟수 점검 (텍스트 및 JSON)
svault guard status -t guarded.svault
svault guard status -t guarded.svault --json

# 47. 데드맨 스위치 체크인(기한 연장) 및 실패 카운터 리셋
svault guard checkin -t guarded.svault --interval 30d
svault guard reset -t guarded.svault

# 48. 가드 해제(Disarm) 및 긴급 즉각 다중 패스 파쇄(Emergency Trigger)
svault guard disarm -t guarded.svault
svault guard trigger -t guarded.svault --force --passes 3

# 49. 신선한 솔트/논스로 컨테이너 비밀번호 안전 회전 (Re-Key)
svault rotate -i vault.svault -o rotated.svault -p "기존비밀번호" -n "신규비밀번호"

# 50. 원자적 임시 파일 기반 인플레이스(In-Place) 파일 덮어쓰기 회전
svault rotate -i vault.svault --in-place -p "기존비밀번호" -n "신규비밀번호"
svault rotate -i stego.bmp --in-place -p "기존비밀번호" -n "신규비밀번호"

# 51. 스테가노그래피 캐리어(PNG, WAV, BMP, ASCII 아머) 자격증명 회전
svault rotate -i carrier.png -o rotated.png -p "기존비밀번호" -n "신규비밀번호"
svault rotate -i carrier.asc -o rotated.asc -p "기존비밀번호" -n "신규비밀번호"

# 52. DPAPI 하드웨어 바인딩 토글 및 시간 정책 소거 회전
svault rotate -i vault.svault -o dpapi.svault -p "기존비밀번호" -n "신규비밀번호" --dpapi
svault rotate -i locked.svault -o unlocked.svault -p "기존비밀번호" -n "신규비밀번호" --clear-policy --json

# 53. 디렉터리 분리형 무결성 카나리 매니페스트 생성
svault canary init -d ./vaults
svault canary init -d ./vaults -p "카나리비밀번호" --json

# 54. 디렉터리 카나리 무결성 및 변조 검증
svault canary verify -d ./vaults
svault canary verify -d ./vaults -p "카나리비밀번호" --strict --json

# 55. 대화형 인메모리 키-값 금고 셸 구동
svault repl -v myvault.svault -p "금고비밀번호"

# 56. 비대화형 배치 명령 즉각 실행 (--exec)
svault repl -v myvault.svault -p "금고비밀번호" --exec "set api_key secret_value --tag prod; set db_pass hunter2; save"

# 57. 비밀번호 조회 시 자동 소거 클립보드에 직접 복사
svault repl -v myvault.svault -p "금고비밀번호" --exec "get api_key --clip --clip-ttl 15"

# 58. 읽기 전용 감사 모드 및 JSON 내보내기
svault repl -v myvault.svault -p "금고비밀번호" --readonly --exec "list" --json
svault repl -v myvault.svault -p "금고비밀번호" --exec "export ./backup.json; exit"
```

### 저작권 및 라이선스

Copyright 2026 **GHSFS** ([https://github.com/GHSFS](https://github.com/GHSFS)).

본 프로젝트는 **Apache License, Version 2.0** ([`LICENSE`](./LICENSE)) 하에 배포되며, 모든 복제본·재배포본·파생 저작물은 Apache-2.0 제4조(d)항에 따라 [`NOTICE`](./NOTICE) 파일에 명시된 **GHSFS** 저작권 및 출처 고지를 반드시 유지해야 합니다.
