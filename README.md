# shadow-vault (`svault`)

> Zero-trust steganography and dual-layer hardware-bound encrypted vault — conceal sensitive files inside ordinary PNG/audio carriers or seal them with Argon2id + ChaCha20-Poly1305 + Windows DPAPI.

[![Build](https://github.com/GHSFS/shadow-vault/actions/workflows/build.yml/badge.svg)](https://github.com/GHSFS/shadow-vault/actions/workflows/build.yml)
[![Tests](https://github.com/GHSFS/shadow-vault/actions/workflows/test.yml/badge.svg)](https://github.com/GHSFS/shadow-vault/actions/workflows/test.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](./LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20x64-0078D6)](#installation)

[English](#english) · [한국어](#한국어)

---

## English

### Overview

`shadow-vault` (`svault.exe`) is a single-binary cryptographic vault and steganography toolkit written in Rust. It is built for operators who need two layers of protection for high-value files (seed phrases, private keys, credentials, research notes):

1. **Dual-Layer Authenticated Encryption (`SVLT` v1)** — combines memory-hard **Argon2id** key derivation + **ChaCha20-Poly1305** AEAD with optional **Windows DPAPI (`CryptProtectData`)** machine/user-session binding. Even if an attacker steals both your `.svault` file and your passphrase, a DPAPI-bound vault cannot be decrypted outside your Windows user account.
2. **Lossless Carrier Steganography** — embeds the encrypted `SVLT` container inside ordinary media files (such as PNG images with valid IEEE 802.3 CRC-32 checksums) so the carrier renders normally in standard viewers while concealing the encrypted payload.

### Features

- **Argon2id + ChaCha20-Poly1305 AEAD** — 128-bit random salt, 96-bit random nonce, domain-separated 256-bit key derivation, and 128-bit Poly1305 authentication tag.
- **Hardware / Session Binding (`--dpapi`)** — wraps ciphertext with Windows DPAPI so decryption is restricted to the originating Windows user profile.
- **Lossless PNG Steganography (`embed` / `extract`)** — injects an `svLt` ancillary chunk before `IEND` with full CRC-32 verification; idempotent re-embedding replaces any prior hidden payload cleanly.
- **Zero-Knowledge Header Inspection (`inspect`)** — view container version, DPAPI binding flag, payload byte size, and salt hex without decrypting.
- **3-Pass Secure File Shredder (`shred`)** — overwrites sensitive plaintext files with `0x00`, `0xFF`, and CSPRNG random bytes before unlinking.
- **Single Static Binary** — compiled with `+crt-static`, `opt-level = "z"`, LTO, and stripped symbols. Zero external runtime dependencies.

### Architecture

```text
  Plaintext File ──▶ [ Argon2id + ChaCha20-Poly1305 ]
                                  │
                     (optional --dpapi)
                                  ▼
                     [ Windows CryptProtectData ]
                                  │
                                  ▼
                       SVLT v1 Container (.svault)
                         ├── Direct disk storage
                         └── Stego Embed ──▶ Ordinary PNG Carrier (.png)
```

### Quick Start

```bash
# 1. Encrypt a file with passphrase + Windows DPAPI hardware binding
svault encrypt -i wallet-seed.txt -o wallet.svault -p "your-strong-passphrase" --dpapi

# 2. Inspect container metadata without decrypting
svault inspect wallet.svault

# 3. Conceal a secret file directly inside a PNG image
svault embed -c wallpaper.png -s wallet-seed.txt -o wallpaper-stego.png -p "your-strong-passphrase" --dpapi

# 4. Extract and decrypt the secret from the PNG image
svault extract -c wallpaper-stego.png -o restored-seed.txt -p "your-strong-passphrase"

# 5. Securely shred the original plaintext file (3 passes)
svault shred wallet-seed.txt --passes 3
```

### License & Attribution

Copyright 2026 **GHSFS** ([https://github.com/GHSFS](https://github.com/GHSFS)).

Licensed under the **Apache License, Version 2.0** ([`LICENSE`](./LICENSE)).
Pursuant to Section 4(d) of the Apache License 2.0, any redistribution or derivative work in Source or Object form must retain the attribution notices in [`NOTICE`](./NOTICE).

---

## 한국어

### 개요

`shadow-vault`(`svault.exe`)는 중요한 파일(시드 문구, 개인키, 자격증명, 보안 문서 등)을 이중으로 보호하고 일반 미디어 파일 내부에 은닉할 수 있는 Rust 기반 단일 바이너리 보안 금고 및 스테가노그래피 도구입니다.

1. **이중 계층 인증 암호화 (`SVLT` v1)** — 메모리 하드 KDF인 **Argon2id** + **ChaCha20-Poly1305** AEAD 암호화에 더해, 선택적으로 **Windows DPAPI (`CryptProtectData`)** 하드웨어/사용자 세션 귀속을 결합합니다. `--dpapi` 옵션을 켜면 암호화된 파일과 비밀번호가 외부로 유출되더라도 **본인의 Windows 계정 세션이 아니면 복호화가 원천 불가능**합니다.
2. **무손실 스테가노그래피 은닉 (`embed` / `extract`)** — 암호화된 컨테이너를 일반 PNG 이미지 내부(`svLt` 청크 + IEEE 802.3 CRC-32 검증)에 손실 없이 숨깁니다. 결과물 이미지는 모든 이미지 뷰어와 브라우저에서 원본과 동일하게 열립니다.

### 주요 기능

- **Argon2id + ChaCha20-Poly1305 AEAD** — 매 암호화마다 새로운 128비트 솔트와 96비트 논스를 생성하며 변조 시 즉시 복호화를 거부합니다.
- **Windows DPAPI 이중 잠금 (`--dpapi`)** — 생성한 Windows 사용자 프로필에 암호문을 하드웨어/세션 단위로 귀속시킵니다.
- **PNG 이미지 은닉 (`embed` / `extract`)** — PNG 표준 청크 규격과 CRC-32 체크섬을 준수하여 이미지 손상 없이 암호화 페이로드를 은닉·추출합니다.
- **컨테이너 헤더 검사 (`inspect`)** — 복호화 없이 컨테이너 버전, DPAPI 귀속 여부, 페이로드 크기, 솔트 값을 즉시 확인합니다.
- **다중 패스 완전 파쇄 (`shred`)** — 원본 평문 파일을 삭제할 때 `0x00` ➔ `0xFF` ➔ 난수 덮어쓰기 후 디스크 동기화 및 길이 0 절삭을 수행해 포렌식 복구를 차단합니다.

### 사용법 요약

```bash
# 1. 파일 암호화 (비밀번호 + Windows DPAPI 이중 잠금)
svault encrypt -i secret.txt -o secret.svault -p "비밀번호" --dpapi

# 2. 평범한 PNG 이미지 속에 비밀 파일 암호화 은닉
svault embed -c photo.png -s secret.txt -o photo_hidden.png -p "비밀번호" --dpapi

# 3. PNG 이미지에서 비밀 파일 추출 및 복호화
svault extract -c photo_hidden.png -o recovered.txt -p "비밀번호"

# 4. 컨테이너 또는 스테고 PNG 메타데이터 조회
svault inspect photo_hidden.png

# 5. 원본 평문 파일 3-패스 완전 파쇄
svault shred secret.txt --passes 3
```

### 저작권 및 라이선스

Copyright 2026 **GHSFS** ([https://github.com/GHSFS](https://github.com/GHSFS)).

본 프로젝트는 **Apache License, Version 2.0** ([`LICENSE`](./LICENSE)) 하에 배포되며, 모든 복제본·재배포본·파생 저작물은 Apache-2.0 제4조(d)항에 따라 [`NOTICE`](./NOTICE) 파일에 명시된 **GHSFS** 저작권 및 출처 고지를 반드시 유지해야 합니다.
