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
5. **Proactive Zeroize Hardening** — wipes sensitive intermediate key derivation buffers, ChaCha20 keys, Shamir polynomials, and DPAPI plaintext from memory upon drop using the `zeroize` crate.

### Features

- **Argon2id + ChaCha20-Poly1305 AEAD** — 128-bit random salt, 96-bit random nonce, domain-separated 256-bit key derivation, and 128-bit Poly1305 authentication tag.
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
5. **선제적 메모리 제로화 보호 (`zeroize`)** — Argon2id 유도 키, ChaCha20 키 버퍼, 샤미르 다항식 계수 및 Windows DPAPI 복호화 평문 버퍼를 스코프 종료 즉시 메모리에서 0x00으로 완전 소거합니다.

### 주요 기능

- **Argon2id + ChaCha20-Poly1305 AEAD** — 매 암호화마다 새로운 128비트 솔트와 96비트 논스를 생성하며 변조 시 즉시 복호화를 거부합니다.
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
```

### 저작권 및 라이선스

Copyright 2026 **GHSFS** ([https://github.com/GHSFS](https://github.com/GHSFS)).

본 프로젝트는 **Apache License, Version 2.0** ([`LICENSE`](./LICENSE)) 하에 배포되며, 모든 복제본·재배포본·파생 저작물은 Apache-2.0 제4조(d)항에 따라 [`NOTICE`](./NOTICE) 파일에 명시된 **GHSFS** 저작권 및 출처 고지를 반드시 유지해야 합니다.
