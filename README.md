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
4. **Shamir's Secret Sharing (`M-of-N` Key Splitting, `src/shamir.rs`)** — mathematically provable information-theoretic secret sharing over $\text{GF}(256)$ with constant-time arithmetic. Split master recovery keys, passphrases, or `.svault` containers into $N$ shares requiring any $M$ shares to reconstruct (`svault split` / `svault combine`).
5. **Passphrase Strength & Carrier Entropy Auditor (`src/audit.rs`)** — evaluates passphrase resiliency via Shannon entropy bits-per-byte, character pool diversity, and predictive vulnerability pattern detection (repeated characters, ascending/descending sequences, keyboard walks, leetspeak dictionary matching). Audits steganography carriers (PNG chunks, WAV RIFF/LSB streams) and encrypted `.svault` containers for anomalies and tampering (`svault audit <target>` / `svault audit -p <passphrase>`).
6. **RFC 6238 TOTP 2FA Vault (`src/totp.rs`)** — zero-dependency encrypted local two-factor authentication secret store sealed inside `.svault` containers. Features RFC 4648 Base32 codec, self-contained RFC 3174 SHA-1, RFC 2104 HMAC (SHA-1/256/512), dynamic truncation, `otpauth://totp/...` URI parser/serializer, constant-time verification against timing attacks, and terminal visual countdown progress bar (`svault totp add`, `svault totp code`, `svault totp list`, `svault totp verify`).
7. **Proactive Zeroize Hardening** — wipes sensitive intermediate key derivation buffers, ChaCha20 keys, Shamir polynomials, TOTP secrets, and DPAPI plaintext from memory upon drop using the `zeroize` crate.

### Features

- **Argon2id + ChaCha20-Poly1305 AEAD** — 128-bit random salt, 96-bit random nonce, domain-separated 256-bit key derivation, and 128-bit Poly1305 authentication tag.
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
- **Zero-Knowledge Header Inspection (`inspect`)** — view container version, DPAPI binding flag, decoy container presence, payload byte size, and salt hex across `.svault`, `.png`, and `.wav` files without decrypting or exposing hidden slot sizes.
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
                                                                              └── WAV Audio (.wav)
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

# 4. Inspect container metadata without decrypting (.svault, .png, or .wav)
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

# 9. Securely shred the original plaintext file (3 passes)
svault shred classified.txt --passes 3

# 10. Split a master recovery key or secret into 3-of-5 Shamir shares
svault split -s "your-master-seed-or-secret" -m 3 -n 5 -o shares/share

# 11. Combine any 3 shares to reconstruct the original secret
svault combine shares/share_1.share shares/share_3.share shares/share_5.share -o restored.txt

# 12. Audit passphrase strength, Shannon entropy, and crack time estimates
svault audit -p "Correct-Horse-Battery-Staple-2026!"

# 13. Audit a stego carrier image or container for anomalies and hidden payloads
svault audit wallpaper-stego.png --json

# 14. Add a TOTP 2FA credential via Base32 secret or otpauth:// URI
svault totp add github --secret "JBSWY3DPEHPK3PXP" --issuer "GitHub" --vault totp.svault -p "vault-pass"
svault totp add --uri "otpauth://totp/Google:alice?secret=JBSWY3DPEHPK3PXP&issuer=Google" --vault totp.svault -p "vault-pass"

# 15. Generate live 2FA OTP code with visual countdown progress bar (or --json)
svault totp code github --vault totp.svault -p "vault-pass"
svault totp code github --vault totp.svault -p "vault-pass" --json

# 16. Verify an OTP code against skew window (+/- 1 step)
svault totp verify github 123456 --skew 1 --vault totp.svault -p "vault-pass"

# 17. List and export 2FA accounts
svault totp list --vault totp.svault -p "vault-pass"
svault totp export github --vault totp.svault -p "vault-pass"
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
4. **샤미르 비밀 공유 (`M-of-N` 키 분할, `src/shamir.rs`)** — $\text{GF}(256)$ 유한체 기반 정보이론적 비밀 분할/복원 엔진. 분기 없는 상수시간(Constant-Time) 연산으로 부채널 공격을 방어하며, 마스터 복구 키, 비밀번호, 대용량 바이너리 금고를 $N$개 조각으로 분할하여 임의의 $M$개 조각으로만 원본을 복원(`svault split` / `svault combine`)합니다. 아머드 텍스트, 한 줄 압축, JSON 직렬화 및 SHA-256/CRC-32 무결성 검증을 지원합니다.
5. **비밀번호 강도 & 스테가노그래피 캐리어 엔트로피 감사기 (`src/audit.rs`)** — 섀넌 엔트로피(Shannon entropy bits/byte), 문자 풀 다양성, 취약 패턴 탐지(반복 문자, 연속 시퀀스, 키보드 워크, 리트스피크 사전 매칭)를 통해 비밀번호 내구성을 감사하고, PNG 청크·WAV 서브청크/LSB 스트림 및 `.svault` 컨테이너의 변조·이상 징후를 정밀 분석(`svault audit <대상>` / `svault audit -p <비밀번호>`)합니다.
6. **RFC 6238 TOTP 2FA 보안 금고 (`src/totp.rs`)** — 외부 라이브러리 의존성 0개의 독립 로컬 암호화 2차 인증(2FA) 금고 엔진. RFC 4648 Base32 코덱, 자체 완비 RFC 3174 SHA-1, RFC 2104 HMAC (SHA-1/256/512), `otpauth://totp/...` URI 파서/직렬화기, 부채널 타이밍 공격을 방어하는 상수시간 검증 및 터미널 시각적 잔여시간 카운트다운 진행바를 지원합니다 (`svault totp add`, `svault totp code`, `svault totp list`, `svault totp verify`).
7. **선제적 메모리 제로화 보호 (`zeroize`)** — Argon2id 유도 키, ChaCha20 키 버퍼, 샤미르 다항식 계수, TOTP 비밀키 및 Windows DPAPI 복호화 평문 버퍼를 스코프 종료 즉시 메모리에서 0x00으로 완전 소거합니다.

### 주요 기능

- **Argon2id + ChaCha20-Poly1305 AEAD** — 매 암호화마다 새로운 128비트 솔트와 96비트 논스를 생성하며 변조 시 즉시 복호화를 거부합니다.
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
- **컨테이너 헤더 검사 (`inspect`)** — 복호화 없이 `.svault`, `.png`, `.wav` 파일의 컨테이너 버전, DPAPI 귀속 여부, 미끼 컨테이너 여부, 페이로드 크기, 솔트 값을 즉시 확인합니다 (은닉 슬롯의 크기는 은폐).
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

# 8. 컨테이너 또는 스테고 미디어(.png, .wav) 메타데이터 조회
svault inspect deniable.svault

# 9. 원본 평문 파일 3-패스 완전 파쇄
svault shred secret.txt --passes 3

# 10. 마스터 복구 키 또는 비밀값을 3-of-5 샤미르 조각(Shamir Shares)으로 분할
svault split -s "마스터-복구-시드문구" -m 3 -n 5 -o shares/share

# 11. 임의의 3개 조각을 결합하여 원본 비밀값 완벽 복원
svault combine shares/share_1.share shares/share_3.share shares/share_5.share -o restored.txt

# 12. 비밀번호 강도, 섀넌 엔트로피 및 크랙 시간 정밀 감사
svault audit -p "안전한-비밀번호-문구-2026!"

# 13. 스테고 이미지/오디오 파일 또는 컨테이너 이상 징후 분석
svault audit photo_hidden.png --json

# 14. Base32 시크릿 또는 otpauth:// URI로 2FA 계정 등록
svault totp add github --secret "JBSWY3DPEHPK3PXP" --issuer "GitHub" --vault totp.svault -p "금고비밀번호"
svault totp add --uri "otpauth://totp/Google:alice?secret=JBSWY3DPEHPK3PXP&issuer=Google" --vault totp.svault -p "금고비밀번호"

# 15. 실시간 6자리 2FA 인증 코드 생성 (시각적 잔여시간 게이지 및 --json 지원)
svault totp code github --vault totp.svault -p "금고비밀번호"
svault totp code github --vault totp.svault -p "금고비밀번호" --json

# 16. 시간 오차 윈도우 기반 OTP 코드 검증 (+/- 1 스텝)
svault totp verify github 123456 --skew 1 --vault totp.svault -p "금고비밀번호"

# 17. 계정 목록 조회 및 otpauth:// URI 내보내기
svault totp list --vault totp.svault -p "금고비밀번호"
svault totp export github --vault totp.svault -p "금고비밀번호"
```

### 저작권 및 라이선스

Copyright 2026 **GHSFS** ([https://github.com/GHSFS](https://github.com/GHSFS)).

본 프로젝트는 **Apache License, Version 2.0** ([`LICENSE`](./LICENSE)) 하에 배포되며, 모든 복제본·재배포본·파생 저작물은 Apache-2.0 제4조(d)항에 따라 [`NOTICE`](./NOTICE) 파일에 명시된 **GHSFS** 저작권 및 출처 고지를 반드시 유지해야 합니다.
