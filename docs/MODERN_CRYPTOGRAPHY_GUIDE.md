# Modern Cryptography Reference Guide (현대 암호학 표준 및 실전 아키텍처 가이드)

> **문서 버전**: v1.0.0  
> **분류**: 차세대 보안·암호화 기술 레퍼런스 및 프로젝트 마일스톤 가이드  
> **대상 플랫폼**: Rust / Node.js / Go 기반 보안 도구 및 시스템 개발 프로젝트  

---

## 📑 목차 (Table of Contents)

1. [PGP의 은퇴와 현대 암호학의 패러다임 변화 (Why PGP is Legacy)](#1-pgp의-은퇴와-현대-암호학의-패러다임-변화)
2. [100% 무료·오픈소스 현대 암호학 2대 표준](#2-100-무료오픈소스-현대-암호학-2대-표준)
   - 2.1 파일 암호화의 절대 표준: `age` (Actually Good Encryption)
   - 2.2 코드·바이너리 서명의 표준: `Minisign` & `ssh-keygen -Y`
3. [차세대 보안 끝판왕 기술 3선](#3-차세대-보안-끝판왕-기술-3선)
   - 3.1 양자내성 암호화 (Post-Quantum Cryptography - PQC: ML-KEM / Kyber)
   - 3.2 하드웨어 보안키 및 생체 인증 바인딩 (FIDO2 / YubiKey / Windows Hello)
   - 3.3 무키 서명 (Keyless Signing: Sigstore / Cosign)
4. [보안 프로젝트(`shadow-vault` 등) 추천 백로그 마일스톤](#4-보안-프로젝트-추천-백로그-마일스톤)
5. [Rust 프로젝트 의존성 및 빠른 구현 스니펫](#5-rust-프로젝트-의존성-및-빠른-구현-스니펫)

---

## 1. PGP의 은퇴와 현대 암호학의 패러다임 변화

1991년 탄생한 **PGP/GPG (OpenPGP)**는 역사적으로 중요한 공헌을 했으나, 현대 보안 표준에서는 심각한 결함으로 인해 사용이 전면 지양되고 있습니다:

| 비교 항목 | 구형 레거시 (PGP / GPG) | 👑 현대 표준 (`age` / `Minisign` / SSH) |
| :--- | :--- | :--- |
| **알고리즘** | 구형 RSA-2048/4096, 낡은 CFB 암호화 모드, SHA-1 레거시 | **X25519 (타원곡선), ChaCha20-Poly1305 (AEAD), Ed25519** |
| **사용성 (UX)** | 수십 줄짜리 거대한 아스키 아머 블록, 복잡한 키 만료일 관리 | **단 62글자 초소형 키 (`age1...`), 단일 명령어 실행** |
| **보안 취약점** | 메일 클라이언트 복호화 오라클 취약점 (EFail), 키스팸 공격 | **현대적 AEAD 인증 암호화로 위변조 탐지 100% 보장** |
| **신뢰 모델** | 난해하고 사실상 붕괴된 신뢰망 (Web of Trust) | **명확한 공개키/개인키 1:1 매핑 및 SSH 공개키 재활용** |
| **비용/라이선스**| 오픈소스지만 구현체가 무겁고 관리가 극도로 복잡함 | **100% 무료 & 영구 오픈소스 (MIT / Apache-2.0 / ISC)** |

---

## 2. 100% 무료·오픈소스 현대 암호학 2대 표준

### 2.1 파일 암호화의 절대 표준: `age` (Actually Good Encryption)
- **제작자**: 전 Google Go 보안팀 리드 Filippo Valsorda
- **라이선스**: BSD 3-Clause / Apache 2.0 (완전 무료, 상업용 무제한 이용 가능)
- **핵심 특징**:
  - 오직 최고 등급의 현대 암호 스위트만 사용: **X25519 (키 교환) + ChaCha20-Poly1305 (대칭 암호화) + HKDF-SHA256**.
  - **SSH 키 연동**: 개발자가 이미 가지고 있는 GitHub SSH 공개키(`~/.ssh/id_ed25519.pub`)로 파일을 즉시 암호화할 수 있음.
  - Rust 공식 구현체인 **`rage` (`age` crate)**가 존재하여 Rust 애플리케이션에 0.1초 만에 네이티브 탑재 가능.

### 2.2 코드·바이너리 서명의 표준: `Minisign` & `ssh-keygen -Y`
- **`Minisign`**: OpenBSD의 `signify` 도구를 기반으로 한 초소형 **Ed25519 디지털 서명 도구** (ISC 라이선스, 100% 무료).
- **`ssh-keygen -Y`**: OpenSSH에 기본 내장되어 있어 **추가 프로그램 설치 0개**로 사용 가능. Git 커밋 서명 및 릴리즈 바이너리 무결성 검증을 PGP 키 없이 SSH 키 하나로 종결.

---

## 3. 차세대 보안 끝판왕 기술 3선

### 3.1 양자내성 암호화 (Post-Quantum Cryptography - PQC)
- **NIST 공식 표준**: 2024년 공식 확정된 **ML-KEM (구 Kyber)** 키 캡슐화 및 **ML-DSA (구 Dilithium)** 디지털 서명.
- **하이브리드 암호화 (Hybrid Cryptography)**:
  - 전통적인 `X25519`와 양자내성 `ML-KEM-768`을 동시에 결합하여 키를 이중 유도.
  - 현재의 고성능을 유지하면서, 미래에 양자 컴퓨터가 개발되더라도 영구적으로 해독 불가능한 "양자 방어막" 구축.

### 3.2 하드웨어 보안키 및 생체 인증 바인딩 (FIDO2 / YubiKey / Windows Hello)
- **개념**: 암호화 키를 메모리나 디스크에 두지 않고, 사용자의 **물리적 보안키(YubiKey)** 또는 **Windows Hello(지문/얼굴 인식 TPM)** 칩셋 내부에 하드웨어적으로 격리.
- **장점**: PC가 통째로 해킹당하거나 파일이 유출되더라도 사용자의 물리적 터치나 생체 인증 없이는 단 1비트도 복호화 불가.

### 3.3 무키 서명 (Keyless Signing: Sigstore / Cosign)
- **개념**: Google, GitHub, Linux Foundation 주도 기술.
- **장점**: 개발자가 개인키 파일을 보관할 필요 없이, GitHub/Google OIDC 로그인 인증을 통해 10분짜리 단기 인증서를 발급받아 서명하고, 분산 투명성 원장(Rekor)에 영구 기록.

---

## 4. 보안 프로젝트 추천 백로그 마일스톤

프로젝트의 `TASK_BACKLOG.md`에 아래 마일스톤들을 순차 배치하면 최첨단 보안 프로젝트로 즉시 도약할 수 있습니다:

```markdown
## Future Advanced Cryptography Milestones
- [ ] **M21 — age-Compatible X25519 Asymmetric Public-Key Sealing (`src/age_box.rs`)**:
  Support recipient public-key encryption using `age1...` Bech32 keys or GitHub `ssh-ed25519` public keys so users can seal vaults for others without sharing passphrases (`svault seal -r <pubkey>`).

- [ ] **M22 — Post-Quantum Kyber (ML-KEM-768) Hybrid Key Encapsulation (`src/pqc.rs`)**:
  Implement hybrid key exchange combining X25519 and NIST ML-KEM-768 to provide future-proof post-quantum resistance against "Harvest Now, Decrypt Later" adversaries.

- [ ] **M23 — Minisign-Compatible Ed25519 Detached Container Signatures (`src/sign.rs`)**:
  Generate and verify compact detached signatures for encrypted vaults and stego carriers (`svault sign <file>` / `svault verify <file> --pubkey <key>`).

- [ ] **M24 — Windows Hello / FIDO2 TPM Hardware-Bound Vault (`src/fido.rs`)**:
  Bind container decryption keys to Windows Hello biometric authentication (TPM 2.0 / WebAuthn) for zero-trust physical device security.
```

---

## 5. Rust 프로젝트 의존성 및 빠른 구현 스니펫

### 5.1 `Cargo.toml` 의존성 추가
```toml
[dependencies]
# 1. age 호환 X25519 비대칭 암호화
age = "0.10"

# 2. Ed25519 초경량 디지털 서명
ed25519-dalek = { version = "2.1", features = ["rand_core"] }

# 3. 양자내성 암호화 (NIST ML-KEM / Kyber)
pqcrypto-kyber = "0.8"
pqcrypto-traits = "0.3"
```

### 5.2 X25519 수신자 공개키 봉인 예시 (Rust)
```rust
use age::secrecy::ExposeSecret;
use std::io::Write;

pub fn encrypt_for_recipient(pubkey_str: &str, plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
    let recipient = pubkey_str.parse::<age::x25519::Recipient>()
        .map_err(|e| anyhow::anyhow!("Invalid age public key: {e}"))?;
        
    let mut encrypted = Vec::new();
    let encryptor = age::Encryptor::with_recipients(vec![Box::new(recipient)])
        .expect("Valid recipient");
        
    let mut writer = encryptor.wrap_output(&mut encrypted)?;
    writer.write_all(plaintext)?;
    writer.finish()?;
    
    Ok(encrypted)
}
```

---
*(문서 끝)*
