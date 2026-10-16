<div align="center">

<p align="center">
  <a href="../../README.md">🇺🇸 English</a> · <strong>🇰🇷 한국어</strong> · <a href="./zh-CN.md">🇨🇳 中文</a> · <a href="./es.md">🇪🇸 Español</a> · <a href="./hi.md">🇮🇳 हिन्दी</a><br />
  <a href="./ar.md">🇸🇦 العربية</a> · <a href="./pt-BR.md">🇧🇷 Português</a> · <a href="./ru.md">🇷🇺 Русский</a> · <a href="./fr.md">🇫🇷 Français</a> · <a href="./id.md">🇮🇩 Bahasa Indonesia</a>
</p>

# shadow-vault (`svault`)

> 제로 트러스트 스테가노그래피 및 이중 계층 하드웨어 귀속 암호화 금고 — 민감한 파일을 일반 PNG/오디오 캐리어 내부에 은닉하고, Argon2id + ChaCha20-Poly1305 + Windows DPAPI로 봉인하거나, 이중 비밀번호 기반의 그럴듯한 부인(Plausible Deniability) 미끼 금고를 구축합니다.

[![Build](https://github.com/GHSFS/shadow-vault/actions/workflows/build.yml/badge.svg)](https://github.com/GHSFS/shadow-vault/actions/workflows/build.yml)
[![Tests](https://github.com/GHSFS/shadow-vault/actions/workflows/test.yml/badge.svg)](https://github.com/GHSFS/shadow-vault/actions/workflows/test.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](../../LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20x64-0078D6)](#-빠른-시작-및-cli-사용법-요약)

</div>

---

## 🛡️ 개요 및 핵심 역량

<details open>
<summary><b>🛡️ 개요 및 핵심 역량</b></summary>
<br>

`shadow-vault`(`svault.exe`)는 중요한 파일(시드 문구, 개인키, 자격증명, 보안 문서 등)을 이중으로 보호하고 일반 미디어 파일 내부에 은닉할 수 있는 Rust 기반 단일 바이너리 보안 금고 및 스테가노그래피 도구입니다.

1. **이중 계층 인증 암호화 (`SVLT` v1/v2)** — 메모리 하드 KDF인 **Argon2id** + **ChaCha20-Poly1305** AEAD 암호화에 더해, 선택적으로 **Windows DPAPI (`CryptProtectData`)** 하드웨어/사용자 세션 귀속을 결합합니다. `--dpapi` 옵션을 켜면 암호화된 파일과 비밀번호가 외부로 유출되더라도 **본인의 Windows 계정 세션이 아니면 복호화가 원천 불가능**합니다.
2. **그럴듯한 부인(Plausible Deniability) 및 미끼(Decoy) 금고 (`src/decoy.rs`)** — 단일 컨테이너 내부에 진짜 극비 데이터(기본 비밀번호로 해제)와 무해한 미끼 데이터(미끼 비밀번호로 해제)를 동시에 봉인합니다. 강압에 의해 비밀번호 제출을 요구받을 때 미끼 비밀번호를 알려주면 **미끼 데이터만 정상 복호화**되며, 배후의 은닉 슬롯은 암호학적 난수(CSPRNG 패딩 및 암호문)와 통계적으로 완벽히 구분되지 않아 존재 자체를 입증할 수 없습니다.
3. **무손실 미디어 스테가노그래피 은닉** — 암호화된 컨테이너를 다양한 일반 미디어 파일 내부에 완벽히 은닉합니다:
   - **PNG 이미지 (`embed` / `extract`)**: 비표준 렌더링에 영향을 주지 않는 `svLt` 청크 + IEEE 802.3 CRC-32 무결성 검증 (미끼 금고 직접 은닉 지원).
   - **WAV 오디오 (`embed-wav` / `extract-wav`)**: RIFF 서브청크 모드(`--mode chunk`) 및 16비트 PCM 오디오 LSB 모드(`--lsb`) 지원 + CRC-32 검증.
   - **BMP 이미지 (`embed-bmp` / `extract-bmp`)**: 24비트 무압축 BMP R/G/B 색상 채널 LSB(최하위 비트) 변조 은닉, 4바이트 행 패딩 완벽 보존 및 12바이트 무결성 봉투(`svLt` 매직, 길이, CRC-32) 탑재.
   - **MP3 오디오 (`embed-mp3` / `extract-mp3`, `src/mp3/`)**: ID3v2.3/ID3v2.4 비공개(`PRIV`) 태그 프레임 은닉 및 MPEG 오디오 Layer III 프레임 간 패딩 은닉, 프레임 동기 검증, 기존 메타데이터(TIT2, TPE1) 보존, CRC-32 무결성 검증 및 가용 용량 산출 지원.
4. **범용 캐리어 용량 측정기 (`capacity`)** — `.bmp`, `.wav`, `.png`, `.mp3` 미디어 파일의 총 캐리어 크기, 실제 은닉 가용 바이트 용량, 스테고 오버헤드를 정밀 산출합니다 (`svault capacity <캐리어> [--json]`).
5. **샤미르 비밀 공유 (`M-of-N` 키 분할, `src/shamir.rs`)** — $\text{GF}(256)$ 유한체 기반 정보이론적 비밀 분할/복원 엔진. 분기 없는 상수시간(Constant-Time) 연산으로 부채널 공격을 방어하며, 마스터 복구 키, 비밀번호, 대용량 바이너리 금고를 $N$개 조각으로 분할하여 임의의 $M$개 조각으로만 원본을 복원(`svault split` / `svault combine`)합니다. 아머드 텍스트, 한 줄 압축, JSON 직렬화 및 SHA-256/CRC-32 무결성 검증을 지원합니다.
6. **비밀번호 강도 & 스테가노그래피 캐리어 엔트로피 감사기 (`src/audit.rs`)** — 섀넌 엔트로피(Shannon entropy bits/byte), 문자 풀 다양성, 취약 패턴 탐지(반복 문자, 연속 시퀀스, 키보드 워크, 리트스피크 사전 매칭)를 통해 비밀번호 내구성을 감사하고, PNG 청크·WAV 서브청크/LSB 스트림·BMP 픽셀 LSB 및 `.svault` 컨테이너의 변조·이상 징후를 정밀 분석(`svault audit <대상>` / `svault audit -p <비밀번호>`)합니다.
7. **RFC 6238 TOTP 2FA 보안 금고 (`src/totp.rs`)** — 외부 라이브러리 의존성 0개의 독립 로컬 암호화 2차 인증(2FA) 금고 엔진. RFC 4648 Base32 코덱, 자체 완비 RFC 3174 SHA-1, RFC 2104 HMAC (SHA-1/256/512), `otpauth://totp/...` URI 파서/직렬화기, 부채널 타이밍 공격을 방어하는 상수시간 검증 및 터미널 시각적 잔여시간 카운트다운 진행바를 지원합니다 (`svault totp add`, `svault totp code`, `svault totp list`, `svault totp verify`).
8. **자동 만료 클립보드 가드 (`src/clipboard_guard.rs`)** — 복호화된 비밀번호, TOTP 2FA 코드, 복구 시드문구를 Windows 클립보드로 안전하게 복사하고 설정된 유효시간(TTL, 예: `--clip-ttl 15`) 후 자동 소거합니다. Windows 10/11 클립보드 기록(Win + V) 및 클라우드 동기화 등록을 원천 차단하는 포맷 메타데이터(`CanIncludeInClipboardHistory`, `ExcludeClipboardContentFromMonitorProcessing`)를 자동 주입하며, 소거 전 SHA-256 상수시간 지문 비교(`constant_time_eq_32`)를 수행해 사용자가 이후에 복사한 다른 클립보드 데이터를 덮어쓰지 않도록 안전하게 보호합니다 (`svault clip`, 및 복호화 명령 시 `--clip`).
9. **리드-솔로몬 / 패리티 오류 정정 아머 (`src/armor.rs`)** — 블록 패리티 복구 스트라이프와 ASCII 아머드 `.svault.asc` 내보내기/가져오기/복구를 지원하여 부분적인 비트 손상(Bit Rot)이나 텍스트 전송 채널 상의 손상에서도 컨테이너를 복원합니다. $\text{GF}(256)$ 상의 코시(Cauchy) 생성 행렬 $[I_K; A]$을 사용하여 MDS(최대 거리 분리) 부호 성질을 보장하므로, 총 $K + M$개 스트라이프 중 임의의 $K$개 온전한 조각만 있으면 모든 원본 데이터를 완벽하게 재구성합니다. 자동 손상 탐지, 자가 치유 복구(`svault repair`), `inspect` 및 `audit` 자동 감지, 자동 만료 클립보드 가드를 결합 지원합니다 (`svault armor`, `svault dearmor`, `svault repair`).
10. **디렉터리 및 다중 파일 매니페스트 패킹 (`src/archive.rs`)** — 전체 디렉터리 트리를 상대 경로 정규화, 다중 계층 Zip Slip / 경로 순회(Path Traversal) 방어, 압축 폭탄(Zip Bomb) 방어, 파일별 SHA-256 암호학적 매니페스트, Unix/Windows 파일 권한 보존과 함께 단일 `SVLT` 컨테이너로 완전 밀봉(`svault pack-dir` / `svault unpack-dir`)합니다. `--list`, `--verify-only`, `--overwrite`, `--json`, `--dpapi` 및 투명한 스테가노그래피(PNG/WAV/BMP/MP3) & ASCII 아머 캐리어 추출을 지원합니다.
11. **키파일 + 비밀번호 이중 인증(2FA) 키 유도 (`src/keyfile.rs`)** — 외장 하드웨어 또는 USB 키파일(`--keyfile <경로>`)을 사용자 비밀번호와 결합하여 64 KiB 스트리밍 HMAC-SHA256 사전 해싱 후 Argon2id로 키를 유도합니다. 비밀번호 + 키파일 이중 인증(2FA) 및 키파일 단독 모드를 모두 지원하며, 내장 CSPRNG 키파일 생성(`svault keyfile generate`), SHA-256 지문 출력(`svault keyfile fingerprint`), 섀넌 엔트로피 감사(`svault keyfile inspect`), 제로화 메모리 소거 및 모든 미디어 스테가노그래피 캐리어·디렉터리 패킹과의 투명한 통합을 지원합니다.
12. **청크 스트리밍 암호화 엔진 (`src/stream.rs`)** — 멀티 기가바이트(Multi-GB) 대용량 파일과 데이터 스트림을 $O(1)$ 고정 RAM 슬라이딩 윈도우로 안전하게 암호화 및 복호화합니다 (기본 4 MiB 청크, 64 KiB–64 MiB 범위). `SVST` v1 바이너리 헤더, 청크별 고유 논스 유도(`SHA256(b"shadow-vault:stream-chunk-nonce:v1" || base_nonce || chunk_index || tag)`), 청크별 AAD 위변조 방어, 시간 잠금/만료 정책 결합 및 Windows DPAPI 스트림 키 하드웨어 귀속을 지원합니다 (`svault stream encrypt`, `svault stream decrypt`, `svault stream inspect`, `--stream`, `--chunk-size`).
13. **스테가노그래피 캐리어 시각/통계적 디프 리포트 (`src/diff.rs`)** — 원본과 스테가노그래피 캐리어 간의 시각 신호 왜곡(MSE, PSNR, MAE, 순수 LSB 변조율), 16비트 오디오 왜곡(SNR, PSNR), 구조적 청크 테이블 정렬 및 섀넌 엔트로피 차이를 비교 분석(`svault compare`)합니다.
14. **데드맨 스위치 & 최대 실패 횟수 자동 파기 가드 (`src/guard.rs`)** — 변조 방지 시도 원장(`.guard` 동반 파일 또는 은닉 전역 원장)을 기반으로 $K$회 연속 인증 실패 시 3단계(0x00, 0xFF, CSPRNG) 영구 파일 파쇄를 자동 실행하며, 비활동 기한 만료 시 셀프 파쇄를 발동하는 데드맨 스위치를 제공합니다 (`svault guard arm`, `svault guard status`, `svault guard checkin`, `svault guard reset`, `svault guard trigger`).
15. **결정론적 & CSPRNG 비밀번호 생성기 (`src/passgen/`)** — 2,048개 BIP-39 단어 사전 기반 다이스웨어(Diceware) 복구 문구 생성, 시각적 혼동 문자 제거(`--exclude-ambiguous`) 패스워드/PIN 생성, Hex/Base64/Base32 원시 암호학적 바이트 토큰 생성, 마스터 시드 결정론적 유도(`--seed`, `--context`), 5단계 엔트로피 내구성 평가 및 자동 만료 클립보드 가드 결합을 지원합니다 (`svault keygen`).
16. **전 서브커맨드 전수 구조화 JSON 출력 모드 (`--json`)** — 모든 서브커맨드(`encrypt`, `decrypt`, `encrypt-decoy`, `decrypt-decoy`, `embed`, `extract`, `embed-wav`, `extract-wav`, `embed-bmp`, `extract-bmp`, `embed-mp3`, `extract-mp3`, `armor`, `dearmor`, `repair`, `shred`, `split`, `combine`, `keyfile`, `totp`, `clip`, `guard`, `pack-dir`, `unpack-dir`, `inspect`, `audit`, `compare`, `keygen`, `rotate`, `canary`)에서 기계 판독 가능한 일관된 표준 JSON 응답(`status`, `command`, 세부 메타데이터, 바이트 크기, 지문)을 제공하여 CI/CD 및 자동화 쉘 스크립트 파이프라인 연계를 지원합니다.
17. **컨테이너 키 교체 및 비밀번호 회전 (`rotate`, `src/rotate.rs`)** — 기존 `.svault` 컨테이너 또는 스테가노그래피 캐리어(PNG, BMP, WAV, MP3, ASCII 아머)를 새로운 비밀번호나 키파일로 재암호화(`svault rotate`)합니다. 매 회전마다 독립적인 16바이트 솔트와 12바이트 논스를 생성하고, Windows DPAPI 하드웨어 귀속 설정 변경(`--dpapi`/`--no-dpapi`), 시간 잠금/만료 정책 보존 또는 제거(`--clear-policy`), 원자적 임시 파일 치환을 지원합니다.
18. **분리형 무결성 매니페스트 및 카나리 검증 (`canary`, `src/canary.rs`)** — 볼트 및 스테가노그래피 캐리어 디렉터리의 변조 여부를 모니터링하는 서명된 SHA-256 카나리 매니페스트를 생성하고 검증(`svault canary init` / `svault canary verify`)합니다. 다중 캐리어 포맷 자동 식별, Argon2id + HMAC-SHA256 서명 인증, 상수 시간 서명 검증, 수정/삭제/미추적 이상 탐지 및 구조화 JSON 출력을 지원합니다.
19. **MP3 ID3v2 & 오디오 프레임 스테가노그래피 엔진 (`src/mp3/`)** — MPEG Audio Layer III 파일 내부에 ID3v2 PRIV 비공개 태그 프레임 은닉, MPEG 프레임 간 패딩 은닉, 투명한 자동 감지, 미끼 금고 그럴듯한 부인 및 캐리어 용량 산출을 제공합니다 (`svault embed-mp3` / `svault extract-mp3`).
20. **FIDO2 & Windows Hello 하드웨어 키 자격증명 바인딩 (`src/hardware_token/`)** — 물리적 FIDO2 USB 보안 키(YubiKey, SoloKey, Nitrokey 등), Windows Hello 생체 인증(TPM 연동), 가상 토큰을 컨테이너 암호화 키에 결합(`--fido2`, `--fido2-cred`, `--fido2-pin`)합니다. W3C WebAuthn 및 CTAP 2.1 PRF (HMAC-secret) 규격을 준수하여 하드웨어 시크릿을 Argon2id 기본 키와 도메인 분리 HMAC-SHA256으로 혼합하고, 전용 바이너리 와이어 헤더(`SVHW`)와 CRC-32 무결성 태그를 ChaCha20-Poly1305 AAD로 검증합니다. 자격증명 등록, 목록, 검증, 삭제 및 회전(`svault fido2`)을 지원합니다.
21. **포스트-양자 하이브리드 키 캡슐화 (`src/pq_kem/`)** — 고전 타원곡선 **X25519** 디피-헬만과 NIST **FIPS 203 ML-KEM-768**(구 Kyber-768) 격자 암호학을 결합한 이중 계층 양자 내성 비대칭 볼트 봉인 엔진. HKDF-SHA256 도메인 분리 키 유도를 통해 ChaCha20-Poly1305 대칭키를 도출하고, 전용 `SVPQ` v1 바이너리 컨테이너 및 PEM 스타일 ASCII 아머를 지원합니다 (`svault kem keygen`, `svault kem seal`, `svault kem open`, `svault kem inspect`).
22. **선제적 메모리 제로화 보호 (`zeroize`)** — Argon2id 유도 키, ChaCha20 키 버퍼, 샤미르 다항식 계수, TOTP 비밀키, 아카이브 페이로드 버퍼, 클립보드 UTF-16 중간 버퍼 및 Windows DPAPI 복호화 평문 버퍼를 스코프 종료 즉시 메모리에서 0x00으로 완전 소거합니다.

</details>

---

## 🏛️ 보안 금고 및 스테가노그래피 아키텍처

<details open>
<summary><b>🏛️ 보안 금고 및 스테가노그래피 아키텍처</b></summary>
<br>

```text
  [ 주 비밀 데이터 ] ──▶ [ ChaCha20-Poly1305 + CSPRNG 패딩 ] ──┐ (은닉 슬롯)
                                                               │
  [ 미끼 페이로드 ]  ──▶ [ ChaCha20-Poly1305 암호화 ]        ──┴─▶ SVLT v2 컨테이너 (.svault)
                                                                     ├── 단독 디스크 저장
                                                                     └── 캐리어 은닉 (PNG/WAV/BMP/MP3)
```

</details>

---

## ⚡ 핵심 암호화 및 스테가노그래피 기능

<details open>
<summary><b>⚡ 핵심 암호화 및 스테가노그래피 기능</b></summary>
<br>

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
- **MP3 ID3v2 & 오디오 프레임 스테가노그래피 (`embed-mp3` / `extract-mp3`)** — MPEG Audio Layer III 오디오 파일 다중 모드 은닉:
  - **ID3v2 비공개 프레임 모드 (`--mode id3v2`)**: ID3v2.3 및 ID3v2.4 `PRIV` 프레임(`Owner: ShadowVault`) 캡슐화, 기존 타이틀/아티스트 메타데이터 완벽 보존 및 구 버전 프레임 원자적 치환.
  - **오디오 프레임 간 패딩 모드 (`--mode frame`)**: 0xFFE/0xFFF 프레임 동기 비트 보존, 유효 프레임 경계 간 무결성 봉투(`svLt` 매직, 길이, 페이로드, CRC-32) 삽입으로 오디오 디코더 재생 영향 없이 투명하게 은닉.
  - **투명한 자동 감지 (`--mode auto`)**: `extract-mp3` 실행 시 ID3v2 태그 및 프레임 간 패딩 데이터를 자동 스캔하여 즉시 추출.
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
  - **투명한 캐리어 & 아머 자동 해제**: `unpack-dir` 실행 시 `.svault.asc` 아머드 문서 및 PNG/WAV/BMP/MP3 스테가노그래피 캐리어로부터 컨테이너를 전자동 추출.
- **범용 캐리어 용량 측정 (`capacity`)** — `.bmp`, `.wav`, `.png`, `.mp3` 미디어의 전체 바이트, 순수 은닉 가용 용량, 12바이트 스테고 봉투 오버헤드를 정밀 계산하며 파이프라인 연동용 `--json` 출력 지원.
- **컨테이너 헤더 검사 (`inspect`)** — 복호화 없이 `.svault`, `.png`, `.wav`, `.bmp`, `.mp3` 파일의 컨테이너 버전, DPAPI 귀속 여부, 미끼 컨테이너 여부, 페이로드 크기, 솔트 값을 즉시 확인합니다 (은닉 슬롯의 크기는 은폐).
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
  - **전 명령어 유니버설 연동**: `encrypt`, `decrypt`, `embed`, `extract`, `embed-wav`, `extract-wav`, `embed-bmp`, `extract-bmp`, `embed-mp3`, `extract-mp3`, `pack-dir`, `unpack-dir`, 디코이 금고 등 전체 암호화 워크플로우에 `--keyfile` / `-k` 완전 결합.
- **청크 스트리밍 암호화 (`stream`)** — 고정 $O(1)$ 메모리 대용량 스트리밍 인증 암호화:
  - **`SVST` v1 바이너리 와이어 포맷**: 38바이트 베이스 헤더(`SVST`, 버전 1, 플래그, 청크 크기, 솔트, 베이스 논스)와 선택적 `SVPO` 정책 헤더 및 DPAPI 암호화 스트림 키 탑재.
  - **청크 논스 및 AAD 암호학적 결합**: 청크마다 고유 논스를 유도하여 IV 재사용을 방지하고, AAD에 청크 인덱스, 태그(중간/종료), 솔트, 정책 해시를 바인딩하여 순서 변경, 누락, 주입 공격을 원천 방어.
  - **전체 파일 메모리 적재 제로(Zero)**: 2개 버퍼 슬라이딩 윈도우로 0바이트부터 수십 기가바이트 파일까지 메모리 고갈 없이 고속 처리.
  - **투명한 자동 감지**: `svault decrypt` 및 `svault inspect`가 스트리밍 컨테이너를 자동 인식하여 스트리밍 엔진으로 즉시 분기.
- **대화형 인메모리 금고 셸 (`repl` / `shell`)** — 단 한 번의 복호화로 키-값 비밀 저장소를 메모리에 적재하여 디스크 평문 저장 없이 안전하게 조회, 추가, 삭제, 내보내기, 가져오기를 수행하는 대화형 REPL 셸: 자동 소거 클립보드 보호(`--clip`), 읽기 전용 감사 모드(`--readonly`), 비대화형 배치 실행(`--exec`), 무중단 원자적 재암호화 저장 지원.
- **다중 패스 완전 파쇄 (`shred`)** — 원본 평문 파일을 삭제할 때 `0x00` ➔ `0xFF` ➔ 난수 덮어쓰기 후 디스크 동기화 및 길이 0 절삭을 수행해 포렌식 복구를 차단합니다.

</details>

---

## 🚀 빠른 시작 및 CLI 사용법 요약

<details open>
<summary><b>🚀 빠른 시작 및 CLI 사용법 요약 (카테고리별 접기 / 펼치기)</b></summary>
<br>

<details open>
<summary><b>🔐 1. 이중 계층 암호화 및 그럴듯한 부인 미끼 금고 (#1 - #5)</b></summary>
<br>

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
```

</details>

<details open>
<summary><b>🖼️ 2. 무손실 미디어 스테가노그래피: PNG, WAV, BMP, MP3 및 용량 측정 (#6 - #13)</b></summary>
<br>

```bash
# 6. WAV 오디오 파일 속에 비밀 파일 암호화 은닉 (서브청크 또는 16비트 PCM LSB)
svault embed-wav -c audio.wav -s secret.txt -o audio_lsb.wav -p "비밀번호" --lsb

# 7. WAV 오디오 파일에서 비밀 파일 추출 및 복호화
svault extract-wav -c audio_lsb.wav -o recovered_audio.txt -p "비밀번호"

# 8. 스테가노그래피 캐리어 용량 측정 (.bmp, .wav, .png, .mp3)
svault capacity photo.bmp
svault capacity audio.wav --json
svault capacity song.mp3

# 9. 24비트 BMP 이미지 속에 비밀 파일 픽셀 LSB 암호화 은닉
svault embed-bmp -c photo.bmp -s secret.txt -o photo_lsb.bmp -p "비밀번호"

# 10. BMP 이미지에서 비밀 파일 추출 후 안전 클립보드로 직접 복사 (15초 후 자동 소거)
svault extract-bmp -c photo_lsb.bmp -p "비밀번호" --clip --clip-ttl 15

# 11. MP3 오디오 파일 속에 비밀 파일 암호화 은닉 (ID3v2 PRIV 프레임 또는 MPEG 프레임 간 패딩)
svault embed-mp3 -c song.mp3 -s secret.txt -o song_stego.mp3 -p "비밀번호" --mode id3v2
svault embed-mp3 -c song.mp3 -s secret.txt -o song_frame.mp3 -p "비밀번호" --mode frame

# 12. MP3 오디오 파일에서 비밀 파일 자동 감지 추출 및 복호화
svault extract-mp3 -c song_stego.mp3 -o recovered_mp3.txt -p "비밀번호"

# 13. 컨테이너 또는 스테고 미디어(.png, .wav, .bmp, .mp3) 메타데이터 조회
svault inspect photo_lsb.bmp
svault inspect song_stego.mp3
```

</details>

<details open>
<summary><b>🧩 3. 평문 파일 완전 파쇄, 샤미르 비밀 분할 및 엔트로피 감사 (#12 - #16)</b></summary>
<br>

```bash
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
```

</details>

<details open>
<summary><b>⏱️ 4. RFC 6238 TOTP 2FA 금고 및 자동 만료 클립보드 가드 (#17 - #23)</b></summary>
<br>

```bash
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
```

</details>

<details open>
<summary><b>🛡️ 5. 코시 리드-솔로몬 오류 정정 아머 및 디렉터리 아카이브 패킹 (#24 - #30)</b></summary>
<br>

```bash
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

# 29. 스테가노그래피 캐리어(PNG, WAV, BMP, MP3) 또는 ASCII 아머로 디렉터리 은닉 패킹
svault pack-dir -i ./my_project -o project.png -p "금고비밀번호" --carrier cover.png
svault pack-dir -i ./my_project -o project.svault.asc -p "금고비밀번호" --armor

# 30. 디렉터리 언패킹, 아카이브 내용 조회 및 무결성 다이제스트 사전 검증
svault unpack-dir -i project.svault -p "금고비밀번호" --list
svault unpack-dir -i project.svault -p "금고비밀번호" --verify-only
svault unpack-dir -i project.svault -o ./restored_project -p "금고비밀번호" --overwrite
```

</details>

<details open>
<summary><b>⏳ 6. 시간 잠금 정책, USB 키파일 2FA 및 대용량 청크 스트리밍 (#31 - #42)</b></summary>
<br>

```bash
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
```

</details>

<details open>
<summary><b>🚨 7. 캐리어 품질 왜곡률 대조, 데드맨 자가 파쇄 가드 및 비밀번호 생성기 (#43 - #53)</b></summary>
<br>

```bash
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

# 51. 스테가노그래피 캐리어(PNG, WAV, BMP, MP3, ASCII 아머) 자격증명 회전
svault rotate -i carrier.png -o rotated.png -p "기존비밀번호" -n "신규비밀번호"
svault rotate -i carrier.asc -o rotated.asc -p "기존비밀번호" -n "신규비밀번호"

# 52. DPAPI 하드웨어 바인딩 토글 및 시간 정책 소거 회전
svault rotate -i vault.svault -o dpapi.svault -p "기존비밀번호" -n "신규비밀번호" --dpapi
svault rotate -i locked.svault -o unlocked.svault -p "기존비밀번호" -n "신규비밀번호" --clear-policy --json

# 53. 디렉터리 분리형 무결성 카나리 매니페스트 생성
svault canary init -d ./vaults
svault canary init -d ./vaults -p "카나리비밀번호" --json
```

</details>

<details open>
<summary><b>💻 8. 디렉터리 카나리 검증, 키 교체 회전 및 인메모리 REPL 셸 (#54 - #59)</b></summary>
<br>

```bash
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

# 59. 호스트 플랫폼 하드웨어 토큰 및 WebAuthn API 지원 현황 조회
svault fido2 status
svault fido2 status --json
```

</details>

<details open>
<summary><b>🔑 9. FIDO2 물리 보안 키 및 Windows Hello 생체 자격증명 바인딩 (#60 - #65)</b></summary>
<br>

```bash
# 60. FIDO2 USB 키 또는 Windows Hello 자격증명 등록
svault fido2 enroll yubikey-5c --type usb --user alice --output ./yubikey.json
svault fido2 enroll hello-tpm --type hello --pin 849201 --json

# 61. 인증자 어서션 및 PRF 유도 시크릿 지문 검증
svault fido2 test ./yubikey.json
svault fido2 test ./yubikey.json --json

# 62. FIDO2 하드웨어 자격증명 결합 컨테이너 암호화
svault encrypt -i secret.txt -o sealed.svault --fido2-cred ./yubikey.json -p "마스터비밀번호"

# 63. 등록된 하드웨어 자격증명으로 컨테이너 복호화
svault decrypt -i sealed.svault -o restored.txt --fido2-cred ./yubikey.json -p "마스터비밀번호"

# 64. 2FA 다중 요소 인증: 키파일 + FIDO2 물리 토큰 (비밀번호 불필요)
svault encrypt -i secret.txt -o mfa.svault -k usb_token.key --fido2-cred ./yubikey.json
svault decrypt -i mfa.svault -o restored.txt -k usb_token.key --fido2-cred ./yubikey.json

# 65. 기존 컨테이너의 FIDO2 하드웨어 자격증명 바인딩 추가 및 해제 회전
svault rotate -i sealed.svault --in-place -p "기존비밀번호" -n "신규비밀번호" --fido2 --fido2-cred ./yubikey.json
svault rotate -i sealed.svault --in-place -p "신규비밀번호" -n "일반비밀번호" --no-fido2 --fido2-cred ./yubikey.json
```

</details>

<details open>
<summary><b>⚛️ 10. 포스트-양자 하이브리드 키 캡슐화 (X25519 + ML-KEM-768) (#66 - #69)</b></summary>
<br>

```bash
# 66. 포스트-양자 하이브리드 키쌍 생성 (X25519 + ML-KEM-768)
svault kem keygen -p recipient.pub -s recipient.key
svault kem keygen -p recipient.pub -s recipient.key --json

# 67. 수신자 공개키로 양자 내성 볼트 봉인 (원시 바이너리 또는 ASCII 아머)
svault kem seal -i classified.txt -o sealed.svault.pq -k recipient.pub
svault kem seal -i classified.txt -o sealed.asc -k recipient.pub --armor --json

# 68. 포스트-양자 컨테이너 메타데이터 검사 (임시 공개키, ML-KEM 암호문 크기, CRC-32)
svault kem inspect -i sealed.svault.pq
svault kem inspect -i sealed.asc --json

# 69. 수신자 개인키로 양자 내성 볼트 해제 및 복호화
svault kem open -i sealed.svault.pq -o restored.txt -k recipient.key
svault kem open -i sealed.asc -o restored.txt -k recipient.key --json
```

</details>

</details>

---

## 🔒 메모리 안전성 및 제로화 보안 설계

<details open>
<summary><b>🔒 메모리 안전성 및 제로화 보안 설계</b></summary>
<br>

- **100% 안전한 Rust 및 상수시간 암호 연산**: 암호화 데이터 처리 경로에 `unsafe` 블록을 일절 배제하였으며, 갈루아체 연산에서 분기 없는 상수시간(Constant-Time) 알고리즘을 적용하여 타이밍 부채널 공격을 원천 방어합니다.
- **메모리 제로화 자동 소거**: 중간 키 스케줄, 평문 버퍼, TOTP 시크릿, PRF 시드는 Drop 시 `zeroize` 크레이트를 통해 컴파일러 최적화 방지 메모리 제로화(Zeroization)를 수행합니다.
- **하드웨어 프로필 귀속**: 선택적 Windows DPAPI 래핑을 통해 암호화 파일이 유출되더라도 생성된 원래 머신 및 Windows 사용자 세션 외부에서는 복호화가 불가능합니다.
- **경로 순회(Zip Slip) 및 압축 폭탄 방어**: 아카이브 패킹/언패킹 시 정규화된 상대 경로 검증, 예약어 차단, 할당 상한 검사를 통해 시스템을 보호합니다.

</details>

---

## 📄 저작권 및 라이선스 고지

<details open>
<summary><b>📄 저작권 및 라이선스 고지</b></summary>
<br>

Copyright 2026 **GHSFS** ([https://github.com/GHSFS](https://github.com/GHSFS)).

본 프로젝트는 **Apache License, Version 2.0** ([`LICENSE`](../../LICENSE)) 하에 배포되며, 모든 복제본·재배포본·파생 저작물은 Apache-2.0 제4조(d)항에 따라 [`NOTICE`](../../NOTICE) 파일에 명시된 **GHSFS** 저작권 및 출처 고지를 반드시 유지해야 합니다.

</details>
