# 🎨 Asset Integrity & Visual Asset Capture Studio Guide

> **규정 선언: 모든 프로젝트 자산(SVG, PNG, GIF, 다이어그램)의 100% 로컬 영구 보존, 프로그램 실제 실행 캡처(SVG/PNG/GIF), 및 GitHub 푸시 전 시각적 렌더링 캡처 검증 게이트 표준**

---

## 📌 2대 절대 원칙 (Two Uncompromising Invariants)

### 1. 외부 이미지 절대 금지 및 100% 로컬 자체 저장 (Zero External Image Dependency)
- **배경 및 위험성**:
  - 외부 이미지 호스팅(Imgur, Postimages, 블로그, 외부 S3 등)을 마크다운 이미지 링크로 사용하면, 해당 외부 서비스의 서비스 종료, 트래픽 차단, 계정 정지, 링크 변경으로 인해 프로젝트 문서에 치명적인 **404 이미지 깨짐(엑스박스)** 현상이 발생합니다.
- **철칙**:
  - 프로젝트에 사용되는 모든 다이어그램(SVG), 아키텍처 구조도, 시연 애니메이션(GIF), 스크린샷(PNG)은 **100% 프로젝트 내부(`docs/assets/...`)에 직접 파일로 커밋/저장**해야 합니다.
  - 마크다운 문서에서는 오직 저장소 상대 경로(`./docs/assets/...` 또는 `../assets/...`)나 본인 리포지토리의 원본 경로만 사용합니다.
  - 예외: 상태 표시용 표준 SVG 배지(`img.shields.io`)는 허용되나, 주요 본문 시각화 이미지는 전량 자체 호스팅을 강제합니다.

---

### 2. GitHub 반영 전 시각적 렌더링 캡처 검증 게이트 (Visual Render Capture Gate)
- **배경 및 위험성**:
  - SVG 파일 내에 XML 예약어(`&`, `<`, `>`, `"`)가 엔티티(`&amp;`, `&lt;` 등)로 이스케이프되지 않은 채 생으로 들어가면, 브라우저의 XML 파서가 `XML Parsing Error`를 발생시켜 화면에 이미지가 전혀 렌더링되지 않고 깨진 이미지 아이콘이 출력됩니다.
  - 또한, SVG `<text>` 요소의 텍스트가 박스 경계를 넘치거나(overflow) 글꼴이 겹치는 레이아웃 결함이 발생할 수 있습니다.
- **철칙**:
  - GitHub에 커밋 및 푸시하기 전, **반드시 실제 브라우저(Puppeteer / Headless Chromium)를 통해 렌더링하고 스크린샷 캡처를 수행하여 시각적 무결성을 인간 또는 AI가 직접 눈으로 확인**해야 합니다.
  - 모든 텍스트는 박스 내부에서 안전하게 줄바꿈(`formatSvgDesc` / `tspan`) 처리되어야 하며, 박스 밖으로 1픽셀도 넘치지 않아야 합니다.

---

## 📸 3. 프로그램 실제 실행 시각 자산 캡처 스튜디오 (`scripts/capture_assets.mjs`)

개발된 프로그램(Rust CLI 바이너리, 보안 분석 유틸리티 등)의 실제 터미널 실행 모습을 **초고화질 SVG, 고해상도 PNG, 동작 시연 GIF** 3종으로 자동 캡처하여 `docs/assets/`에 영구 보존합니다:

```powershell
# 1. 원클릭 3종 세트 일괄 자동 캡처 (프로젝트 자동 감지 -> SVG, PNG, GIF 생성)
node scripts/capture_assets.mjs auto-capture

# 2. 벡터 터미널 SVG 생성 (확대해도 절대 깨지지 않는 다크모드 창)
node scripts/capture_assets.mjs svg --cmd "cargo run -- inspect target.exe" --out docs/assets/demo.svg

# 3. 고해상도 Retina PNG 캡처 (Headless Chrome / Puppeteer 렌더링)
node scripts/capture_assets.mjs png --cmd "cargo run -- inspect target.exe" --out docs/assets/demo.png

# 4. 터미널 타이핑 & 실행 시연 애니메이션 GIF 생성 (내장 GIF89a 인코더)
node scripts/capture_assets.mjs gif --cmd "cargo run -- inspect target.exe" --out docs/assets/demo.gif
```

### 포맷별 특징 및 산출물:
- **SVG (`terminal_demo.svg`)**: 10~25KB 초경량 벡터 그래픽. macOS/Windows 터미널 창 프레임, ANSI 컬러 구문 강조, 100% XML 엔티티 이스케이프 보장.
- **PNG (`terminal_demo.png`)**: Headless Chromium으로 2x DPI Retina 스크린샷 캡처. 웹 및 모바일에서 선명하게 렌더링.
- **GIF (`demo.gif`)**: 명령어 타이핑 애니메이션 ➔ 실행 결과 스트리밍 ➔ 완료 후 정지(Pause) ➔ 무한 루프 반복. 외부 라이브러리 없이 자체 인코딩.

---

## 🛠️ 4. 자동 검증 러너 (`scripts/verify_assets.mjs`)

본 툴킷에 포함된 `scripts/verify_assets.mjs`를 실행하면 아래 3단계 검증이 전자동으로 수행됩니다:

```powershell
# 1. 일반 검증 (외부 이미지 누출 검사 + SVG XML 문법 정밀 감사)
node scripts/verify_assets.mjs

# 2. 브라우저 렌더링 스크린샷 자동 캡처 검증 (Puppeteer 헤드리스 구동)
node scripts/verify_assets.mjs --capture
```

### 자동 수행 내역:
1. **외부 이미지 누출 전수 스캔**: 프로젝트 내 모든 `.md` 파일에서 `http://`, `https://` 외부 이미지 참조를 탐지하여 경고 및 차단.
2. **SVG XML 엔티티 파서 검사**: 생 `&` 문자, 태그 열림/닫힘 불일치 등 파싱 오류 원천 적발.
3. **Headless 브라우저 렌더링 캡처**: 실제 렌더링 결과물을 `docs/render_verification_captured.png`로 캡처하여 저장.
