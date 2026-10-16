<div align="center">

<p align="center">
  <a href="../../README.md">🇺🇸 English</a> · <a href="./ko.md">🇰🇷 한국어</a> · <strong>🇨🇳 中文</strong> · <a href="./es.md">🇪🇸 Español</a> · <a href="./hi.md">🇮🇳 हिन्दी</a><br />
  <a href="./ar.md">🇸🇦 العربية</a> · <a href="./pt-BR.md">🇧🇷 Português</a> · <a href="./ru.md">🇷🇺 Русский</a> · <a href="./fr.md">🇫🇷 Français</a> · <a href="./id.md">🇮🇩 Bahasa Indonesia</a>
</p>

# shadow-vault (`svault`)

> 零信任隐写术与双层硬件绑定加密保险库 —— 将敏感文件隐匿在普通 PNG/音频载体中，通过 Argon2id + ChaCha20-Poly1305 + Windows DPAPI 密封，或嵌入双密码合理抗辩诱饵保险库。

[![Build](https://github.com/GHSFS/shadow-vault/actions/workflows/build.yml/badge.svg)](https://github.com/GHSFS/shadow-vault/actions/workflows/build.yml)
[![Tests](https://github.com/GHSFS/shadow-vault/actions/workflows/test.yml/badge.svg)](https://github.com/GHSFS/shadow-vault/actions/workflows/test.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](../../LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20x64-0078D6)](#-cli-)

</div>

---

## 🛡️ 项目概述与核心能力

<details open>
<summary><b>🛡️ 项目概述与核心能力</b></summary>
<br>

`shadow-vault` (`svault.exe`) 是一个采用 Rust 编写的零依赖单二进制加密保险库与隐写工具箱，专为需要对高价值凭据（助记词、私钥、核心机密、研究文档）提供军事级保护的专业人员设计：

1. **双层认证加密 (`SVLT` v1/v2)** — 深度结合内存硬化 **Argon2id** 密钥派生与 **ChaCha20-Poly1305** AEAD，配合可选的 **Windows DPAPI (`CryptProtectData`)** 机器/用户会话强绑定。即使文件与主密码被物理窃取，离开原 Windows 用户会话仍无法解密。
2. **合理抗辩与诱饵保险库 (`src/decoy.rs`)** — 在单个容器中同时封装核心机密与无害诱饵数据。在胁迫情境下输入诱饵密码仅解密诱饵数据，隐藏的主槽位在统计学上与均匀随机噪声完全一致（CSPRNG 填充与 ChaCha20 密文）。
3. **无损载体隐写隐蔽传输** — 支持多种日常媒体载体：
   - **PNG 图像**: 在 `IEND` 块前注入 `svLt` 私有辅助数据块，携带 IEEE 802.3 CRC-32 校验。
   - **WAV 音频**: 支持 RIFF/WAVE 子数据块 (`svLt`) 与 16 位 PCM 音频样本最低有效位 (LSB) 替换。
   - **BMP 图像**: 24 位未压缩 RGB 像素通道 LSB 隐写，严格保持 4 字节行对齐填充并封装 12 字节防篡改信封。
   - **MP3 音频 (`src/mp3/`)**: 利用 ID3v2 `PRIV` 私有帧或 MPEG Audio Layer III 帧间填充隐匿加密载荷。
4. **通用载体容量估算 (`capacity`)** — 评估 `.bmp`, `.wav`, `.png`, `.mp3` 载体的可用隐写容量与开销。
5. **Shamir 门限秘密共享 (`M-of-N`, `src/shamir.rs`)** — $\text{GF}(256)$ 恒定时间无分支多项式运算，将主密钥或保险库拆分为 $N$ 份份额，任意 $M$ 份即可恢复。
6. **密码强度与载体熵审计器 (`src/audit.rs`)** — 计算香农熵 (Shannon Entropy)，扫描弱密码模式（键盘走线、重复字符、Leetspeak 字典），审计载体异常。
7. **RFC 6238 TOTP 2FA 保险库 (`src/totp.rs`)** — 零外部依赖本地双因素认证，自完备 Base32、SHA-1/256/512 HMAC，防时序侧信道攻击，终端动态倒计时。
8. **自动过期剪贴板守卫 (`src/clipboard_guard.rs`)** — 抑制 Windows 10/11 剪贴板历史记录 (Win + V) 与云同步，设定 TTL 后自动擦除，并经由 SHA-256 恒定时间指纹比对防止误删。
9. **柯西 Reed-Solomon / 纠错装甲 (`src/armor.rs`)** — $\text{GF}(256)$ 柯西生成矩阵保证 MDS 特性，任意 $K$ 块完好即可重构 $K+M$ 块全量数据，抵御传输损坏与位翻转。
10. **目录与多文件清单打包 (`src/archive.rs`)** — 具备路径穿越 (Zip Slip) 防护、压缩炸弹防护与逐文件 SHA-256 清单验证。
11. **Keyfile + 密码双因素密钥派生 (`src/keyfile.rs`)** — 结合物理 USB Keyfile 与流式 64 KiB HMAC-SHA256 预哈希。
12. **分块流式加密 (`src/stream.rs`)** — 4 MiB 认证分块，独立 Nonce 派生，以 $O(1)$ 常数内存加密数 GB 超大文件。
13. **隐写载体视觉/声学差异报告 (`src/diff.rs`)** — 计算 MSE, PSNR, MAE, SNR 与香农熵位移 $\Delta H$。
14. **死人开关与密码错误自毁防御 (`src/guard.rs`)** — 连续 $K$ 次密码错误自动触发 3 阶段 (0x00, 0xFF, CSPRNG) 物理粉碎，支持非活动超时自毁。
15. **BIP-39 与 CSPRNG 密码生成器 (`src/passgen/`)** — 2,048 词 Diceware 助记词生成与无歧义字符密码生成。
16. **统一结构化 JSON 输出 (`--json`)** — 全命令支持机读 JSON，便于 CI/CD 与自动化脚本调用。
17. **容器密钥轮转 (`rotate`)** — 在不解密为明文落盘的前提下，原子化更换盐值、Nonce 与主密码/硬件绑定。
18. **目录完整性金丝雀探针 (`canary`)** — 批量生成并校验受防篡改签名的 SHA-256 完整性清单。
19. **FIDO2 / Windows Hello 硬件凭据绑定 (`src/hardware_token/`)** — CTAP2 PRF (HMAC-Secret) 与 Argon2id 混合派生，绑定物理 YubiKey 或 TPM 生物识别。
20. **后量子混合密钥封装 (`src/pq_kem/`)** — 经典 X25519 ECDH + NIST FIPS 203 ML-KEM-768 双层后量子抗性密钥封装。
21. **全链路内存主动清零 (`zeroize`)** — 关键缓冲区与密钥调度表在 Drop 时自动覆写清零。

</details>

---

## 🏛️ 存储与隐写架构

<details open>
<summary><b>🏛️ 存储与隐写架构</b></summary>
<br>

```text
  [ Primary Secret ] ──▶ [ ChaCha20-Poly1305 + CSPRNG Pad ] ──┐ (Hidden Slot)
                                                                 │
  [ Decoy Payload ]  ──▶ [ ChaCha20-Poly1305 Encrypted ]     ──┴─▶ SVLT v2 Container (.svault)
                                                                        ├── Direct disk storage
                                                                        └── Stego Carrier (PNG/WAV/BMP/MP3)
```

</details>

---

## 🚀 快速开始与 CLI 工作流

<details open>
<summary><b>🚀 快速开始与 CLI 工作流</b></summary>
<br>

```bash
# 1. 使用密码与 Windows DPAPI 硬件绑定加密文件
svault encrypt -i wallet-seed.txt -o wallet.svault -p "your-strong-passphrase" --dpapi

# 2. 加密包含真实机密与诱饵数据的合理抗辩保险库
svault encrypt -i classified.txt --decoy shopping-list.txt -o deniable.svault \
  -p "primary-secret-pass" --decoy-passphrase "decoy-harmless-pass" --padding 512

# 3. 使用诱饵密码解密（仅释放无害数据）
svault decrypt -i deniable.svault -o revealed.txt -p "decoy-harmless-pass"
# 使用主密码解密（还原真实机密）
svault decrypt -i deniable.svault -o restored.txt -p "primary-secret-pass"

# 4. 无需解密直接检查保险库元数据
svault inspect deniable.svault

# 5. 将诱饵保险库无损隐写嵌入 PNG 图像
svault embed -c wallpaper.png -s classified.txt --decoy shopping-list.txt -o wallpaper-stego.png \
  -p "primary-secret-pass" --decoy-passphrase "decoy-harmless-pass"

# 6. 从 PNG 图像中提取真实机密
svault extract -c wallpaper-stego.png -o restored-seed.txt -p "primary-secret-pass"

# 7. 评估密码强度与香农熵
svault audit -p "P@ssw0rd1234"
svault audit -p "correct-horse-battery-staple-2026" --json

# 8. 启用连续 3 次密码错误自毁防御
svault guard arm -i wallet.svault --max-attempts 3

# 9. 后量子混合密钥对生成与保险库封装 (X25519 + ML-KEM-768)
svault kem keygen -p recipient.pub -s recipient.key
svault kem seal -i classified.txt -o sealed.svault.pq -k recipient.pub
svault kem open -i sealed.svault.pq -o restored.txt -k recipient.key
```

</details>

---

## 🔒 内存安全与零化保障

<details open>
<summary><b>🔒 内存安全与零化保障</b></summary>
<br>

- **100% 内存安全 Rust 与常数时间密码运算**：核心密码路径无 `unsafe`，伽罗瓦域运算恒定时间分支，杜绝侧信道攻击。
- **主动内存零化清零**：关键密钥表、明文缓冲区与 PRF 种子在 Drop 时由 `zeroize` 自动覆写清零。
- **硬件会话绑定**：可选 Windows DPAPI 硬件绑定，离开本机与当前登录会话即无法解密。
- **防路径穿越与压缩炸弹**：严格的 Zip Slip 防护与内存分配硬上限。

</details>

---

## 📄 版权与许可声明

<details open>
<summary><b>📄 版权与许可声明</b></summary>
<br>

Copyright 2026 **GHSFS** ([https://github.com/GHSFS](https://github.com/GHSFS)).

本项目采用 **Apache License, Version 2.0** ([LICENSE](../../LICENSE)) 授权。依照 Apache-2.0 第 4(d) 条规定，任何派生作品与再分发版本均需完整保留 [NOTICE](../../NOTICE) 文件中的版权与致谢声明。

</details>
