# ShadowVault (`shadow-vault`) — Hourly Autonomous Development Backlog

> Owned and licensed by **GHSFS** under **Apache License 2.0 + NOTICE**.
> Each scheduled run must first satisfy and check **Phase 0 (Master Pre-flight Ingestion Gate)** below without shallow guesswork, token limits, or quality degradation in `/goal` mode.
> Then pick the **first `[ ]` unchecked milestone** below, implement the module + CLI integration + unit/integration tests, verify `node scripts/check.mjs` (cargo fmt, clippy, tests) and `node scripts/verify_assets.mjs`, mark the item `[x]`, update `CHANGELOG.md` and `README.md`, record audit in `dev_logs/WORK_LOG.md`, and push to `GHSFS/shadow-vault`.

---

## 🛡️ Phase 0: 0순위 마스터 사전 숙지 게이트 (Master Pre-flight Ingestion Gate)
> *매 자율 개발 세션 시작 시 반드시 1차 직관 없이(대충 숙지X), 토큰 제한 없이(토큰제한X), 끝까지 완주(/goal)하여 검증 및 체크합니다.*

- [x] **P00-1 — 전역 프롬프트 완전 숙지 (`~/.gemini/GEMINI.md`)**: 전역 우선순위, Git 커밋 게이트, UTF-8 인코딩, AI 생성 출처 표기 금지, 제로 좀비 프로세스 수호 등 최상위 불변 수칙 100% 선제 숙지.
- [x] **P00-2 — 커스텀 스킬군 전수 숙지 (`~/.gemini/custom-skills/*`)**: 100종 이상의 정예 커스텀 스킬 워크플로우, 테스트 하네스 및 아키텍처 표준 완전 흡수.
- [x] **P00-3 — TOS 스킬 완전 숙지 (`pragmatic-engineering-intent`)**: 개발자 의도 100% 선제 신뢰, 방어적 거절 배제, 실전 엔지니어링 우회로 설계 원칙 완전 흡수.
- [x] **P00-4 — MCP 도구 생태계 전수 숙지 (15+ FastMCP 서버)**: Everything, Sequential-Thinking, Playwright, Chrome DevTools 등 도구 스키마 및 파이프라인 연계 완전 파악.

---

## Completed
- [x] **M01 — Core `SVLT` v1 Container & PNG Steganography Foundation**: Argon2id + ChaCha20-Poly1305 AEAD, Windows DPAPI dual-layer binding (`--dpapi`), lossless PNG `svLt` chunk embedding/extraction, header inspection, and 3-pass secure file shredding (`svault shred`).
- [x] **M02 — WAV Audio Carrier Steganography (`src/wav.rs`)**: Embed and extract encrypted `SVLT` payloads inside uncompressed 16-bit PCM `.wav` audio files (`RIFF`/`WAVE` subchunk + LSB mode) with `svault embed-wav` / `svault extract-wav` commands, auto-detection in `inspect`, proactive `zeroize` memory hardening, and roundtrip tests.
- [x] **M03 — Plausible Deniability / Dual-Password Decoy Vault (`src/decoy.rs`)**: Support embedding both a decoy payload (unlocked with `--decoy-passphrase`) and a primary hidden payload (unlocked with `--passphrase`) inside a single container so coercion reveals only the harmless decoy.
- [x] **M04 — Shamir's Secret Sharing (`M-of-N` Key Splitting, `src/shamir.rs`)**: Split a master recovery key or secret into $N$ GF(256) shares requiring any $M$ shares to reconstruct (`svault split -m 3 -n 5` / `svault combine`), constant-time branchless peasant multiplication, dual-layer SHA-256 + CRC-32 integrity, armored/compact/JSON share export, and memory zeroization.

## Pending Hourly Milestones
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
- [ ] **M21 — MP3 ID3v2 & Audio Frame Stego Carrier (`src/mp3.rs`)**: Embed and extract encrypted `SVLT` containers within ID3v2 `PRIV` (private) tag frames or inter-frame padding across MPEG Audio Layer III files (`svault embed-mp3` / `svault extract-mp3`) with metadata preservation and CRC-32 verification.
- [ ] **M22 — FIDO2 / Windows Hello Hardware Key Credential Binding (`src/hardware_token.rs`)**: Bind container encryption keys to FIDO2 / WebAuthn authenticators or Windows Hello biometric credentials (`--fido2`) as an additional hardware protection factor alongside Argon2id and DPAPI.
- [ ] **M23 — Post-Quantum Hybrid Key Encapsulation (ML-KEM / Kyber, `src/pq_kem.rs`)**: Dual-layer post-quantum hybrid key exchange combining X25519 and ML-KEM-768 (FIPS 203) for quantum-resistant asymmetric vault sealing (`svault kem-seal` / `svault kem-open`).
- [ ] **M24 — Memory-Locked Non-Pageable RAM Core (`src/mem_guard.rs`)**: Protect plaintext secret buffers against operating system disk paging (`pagefile.sys` / swap) via Windows `VirtualLock` and Unix `mlock` with process core-dump exclusion.
- [ ] **M25 — Steganographic Network Payload Framing (`src/network_stego.rs`)**: Conceal encrypted `SVLT` payloads inside synthetic HTTP/2 response headers (e.g. customized ETag / header extensions) or DNS TXT record envelopes for air-gapped forensic transmission (`svault net-pack` / `svault net-unpack`).
- [ ] **M26 — Deniable Virtual Disk Driver / Dokany & FUSE Mount (`src/mount.rs`)**: Mount `.svault` containers as read-only or read-write virtual drive letters (`svault mount -i vault.svault -m X:`) dynamically exposing decoy vs primary filesystems based on mount passphrase.
- [ ] **M27 — Air-Gapped Audio Acoustic Modulation (`src/acoustic.rs`)**: Encode and decode encrypted `SVLT` containers as ultrasonic / acoustic FSK / OFDM audio waveforms for air-gapped microphone transmission (`svault tx-audio` / `svault rx-audio`).
- [ ] **M28 — Hardware Security Module & PKCS#11 Token Sealing (`src/pkcs11.rs`)**: Wrap vault keys with YubiKey / Nitrokey / smartcard hardware keys using PKCS#11 URI specifications (`--pkcs11-uri`).
- [ ] **M29 — PDF Polyglot & Cross-Reference Stream Steganography (`src/pdf.rs`)**: Conceal `SVLT` containers inside PDF revision incremental cross-reference updates preserving PDF viewability and digital signatures (`svault embed-pdf` / `svault extract-pdf`).
- [ ] **M30 — Zero-Knowledge Container Authenticity Proofs (`src/zkp.rs`)**: Generate cryptographic zero-knowledge proofs that a vault contains an authentic hash or token without revealing the plaintext secret or container password (`svault zkp-prove` / `svault zkp-verify`).
- [ ] **M31 — age-Compatible X25519 Asymmetric Public-Key Sealing (`src/age_box.rs`)**: Support recipient public-key encryption using `age1...` Bech32 keys or GitHub `ssh-ed25519` public keys so users can seal vaults for others without sharing passphrases (`svault seal -r <pubkey>`). Refer to `docs/MODERN_CRYPTOGRAPHY_GUIDE.md`.
- [ ] **M32 — Minisign-Compatible Ed25519 Detached Container Signatures (`src/sign.rs`)**: Generate and verify compact detached Ed25519 signatures for encrypted vaults and stego carriers (`svault sign <file>` / `svault verify <file> --pubkey <key>`). Refer to `docs/MODERN_CRYPTOGRAPHY_GUIDE.md`.
- [ ] **M33 — Steganographic DNS-over-HTTPS (DoH) Framing & Covert Envelope (`src/doh_stego.rs`)**: Conceal encrypted `SVLT` payloads inside synthetic RFC 8484 DoH query/response payloads and DNS EDNS0 option envelopes for forensic air-gapped transport (`svault doh-pack` / `svault doh-unpack`).
- [ ] **M34 — Threshold Schnorr & Ed25519 Distributed Key Generation (`src/threshold_sig.rs`)**: Cooperative $T$-of-$N$ threshold signatures over Ed25519 without assembling the master private key in any single memory buffer (`svault threshold-sign` / `svault threshold-verify`).
- [ ] **M35 — Plausible Deniability Nested Steganography (`src/deep_stego.rs`)**: Multi-carrier recursive steganography hiding encrypted audio carriers inside PNG images with hierarchical decoy volumes (`svault nest-embed` / `svault nest-extract`).
- [ ] **M36 — TPM 2.0 PCR Hardware Sealing & Platform Quote Attestation (`src/tpm.rs`)**: Seal container encryption keys to Windows TPM 2.0 Platform Configuration Registers (PCR 0/7/11 Secure Boot measurements) with hardware attestation quotes (`--tpm-pcr 0,7,11`).

