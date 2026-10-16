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
[![Platform](https://img.shields.io/badge/platform-Windows%20x64-0078D6)](#-快速开始与-cli-工作流)

</div>

---

## 🛡️ 项目概述与核心能力

<details open>
<summary><b>🛡️ 项目概述与核心能力</b></summary>
<br>

`shadow-vault` (`svault.exe`) 是一个采用 Rust 编写的零依赖单二进制加密保险库与隐写工具箱，专为需要对高价值文件（助记词、私钥、凭证、核心机密、研究文档）提供高强度保护的专业人员设计：

1. **双层认证加密 (`SVLT` v1/v2)** — 深度结合内存硬化 **Argon2id** 密钥派生与 **ChaCha20-Poly1305** AEAD，配合可选的 **Windows DPAPI (`CryptProtectData`)** 机器/用户会话强绑定。即使文件与主密码被物理窃取，离开原 Windows 用户会话仍无法解密。
2. **合理抗辩与诱饵保险库 (`src/decoy.rs`)** — 在单个容器中同时封装核心机密（主密码解密）与无害诱饵数据（诱饵密码解密）。在胁迫情境下输入诱饵密码仅解密诱饵数据，隐藏的主槽位在统计学上与均匀随机噪声完全一致（CSPRNG 填充与 ChaCha20-Poly1305 密文），无法证实其存在。
3. **无损载体隐写隐蔽传输** — 将加密容器无缝隐匿在多种日常媒体载体中：
   - **PNG 图像 (`embed` / `extract`)**: 在 `IEND` 块前注入 `svLt` 私有辅助数据块，携带有效 IEEE 802.3 CRC-32 校验（支持诱饵保险库直接嵌入）。
   - **WAV 音频 (`embed-wav` / `extract-wav`)**: 支持 RIFF/WAVE 子数据块模式 (`--mode chunk`) 与 16 位 PCM 音频样本最低有效位 (LSB) 替换模式 (`--lsb`)，带 CRC-32 校验。
   - **BMP 图像 (`src/bmp.rs`)**: 24 位未压缩 RGB 像素通道 LSB 隐写，严格保持 4 字节行对齐填充并封装 12 字节防篡改信封 (`svLt` 魔数、长度、有效载荷、CRC-32)。
   - **MP3 音频 (`src/mp3/`)**: 利用 ID3v2.3/ID3v2.4 `PRIV` 私有标签帧或 MPEG Audio Layer III 帧间填充隐匿加密载荷，具备帧同步校验、元数据保留 (TIT2, TPE1)、CRC-32 校验与容量估算。
4. **通用载体容量估算 (`capacity`)** — 精确评估 `.bmp`, `.wav`, `.png`, `.mp3` 载体的总大小、可用隐写字节容量与开销 (`svault capacity <carrier> [--json]`)。
5. **Shamir 门限秘密共享 (`M-of-N` 密钥拆分, `src/shamir.rs`)** — $\text{GF}(256)$ 恒定时间无分支多项式运算，将主恢复密钥、密码或大容量容器拆分为 $N$ 份份额，任意 $M$ 份即可恢复 (`svault split` / `svault combine`)。支持装甲文本、单行压缩、JSON 序列化与 SHA-256/CRC-32 完整性验证。
6. **密码强度与载体熵审计器 (`src/audit.rs`)** — 计算香农熵 (Shannon Entropy bits/byte)、字符池多样性并扫描弱密码模式（键盘走线、重复字符、递增序列、Leetspeak 字典匹配）。审计 PNG 块、WAV RIFF/LSB 流、24 位 BMP 像素 LSB 与 `.svault` 容器的异常与篡改痕迹 (`svault audit <target>` / `svault audit -p <passphrase>`)。
7. **RFC 6238 TOTP 2FA 保险库 (`src/totp.rs`)** — 零外部依赖本地双因素认证，密封在 `.svault` 容器中。具备 RFC 4648 Base32 编解码、RFC 3174 SHA-1、RFC 2104 HMAC (SHA-1/256/512)、`otpauth://totp/...` URI 解析器/序列化器，防时序侧信道恒定时间验证与终端动态倒计时进度条 (`svault totp add`, `svault totp code`, `svault totp list`, `svault totp verify`)。
8. **自动过期剪贴板守卫 (`src/clipboard_guard.rs`)** — 安全复制解密凭证到 Windows 剪贴板，设定 TTL 后自动擦除（如 `--clip-ttl 15`）。自动注入 Windows 10/11 格式元数据 (`CanIncludeInClipboardHistory`, `ExcludeClipboardContentFromMonitorProcessing`) 以抑制剪贴板历史记录 (Win + V) 与云同步，并在清除前执行 SHA-256 恒定时间指纹比对 (`constant_time_eq_32`) 避免误删用户后续复制的内容。
9. **柯西 Reed-Solomon / 纠错装甲 (`src/armor.rs`)** — 添加块奇偶校验恢复条带与 ASCII 装甲 `.svault.asc` 导入/导出/修复，抵抗传输损坏与位翻转。在 $\text{GF}(256)$ 上使用柯西生成矩阵 $[I_K; A]$ 保证 MDS 特性，任意 $K$ 块完好即可重构 $K+M$ 块全量数据。支持自动损坏检测、自愈修复 (`svault repair`) 以及在 `inspect` 和 `audit` 中自动识别。
10. **目录与多文件清单打包 (`src/archive.rs`)** — 具备相对路径规范化、多层级 Zip Slip / 路径穿越防护、压缩炸弹防护、逐文件 SHA-256 清单验证与 Unix/Windows 文件权限保留，密封为单个 `SVLT` 容器 (`svault pack-dir` / `svault unpack-dir`)。支持 `--list`, `--verify-only`, `--overwrite`, `--json`, `--dpapi` 及透明载体/装甲解包。
11. **Keyfile + 密码双因素密钥派生 (`src/keyfile.rs`)** — 结合外部硬件或 USB Keyfile (`--keyfile <path>`) 与用户密码，经 64 KiB 流式 HMAC-SHA256 预哈希后由 Argon2id 派生密钥。支持密码 + Keyfile 双因素与 Keyfile 单独模式，内置 CSPRNG Keyfile 生成 (`svault keyfile generate`)、SHA-256 指纹输出与全载体透明集成。
12. **分块流式加密 (`src/stream.rs`)** — 4 MiB 认证分块，独立 Nonce 派生 (`SVST` v1 容器)，以 $O(1)$ 常数内存加密数 GB 超大文件，支持 Windows DPAPI 流密钥保护、时间锁定/过期策略及透明流式 CLI。
13. **隐写载体视觉/声学差异报告 (`src/diff.rs`)** — 评估原始与隐写载体之间的视觉失真 (MSE, PSNR, MAE, 纯 LSB 翻转率)、音频失真 (SNR, PSNR)、结构块表对齐与香农熵位移 $\Delta H$ (`svault compare <original> <stego>`)。
14. **死人开关与密码错误自毁防御 (`src/guard.rs`)** — 连续 $K$ 次密码错误自动触发 3 阶段 (0x00, 0xFF, CSPRNG) 物理粉碎，支持非活动超时自毁死人开关 (`svault guard arm`, `svault guard status`, `svault guard checkin`, `svault guard reset`, `svault guard trigger`)。
15. **BIP-39 与 CSPRNG 密码生成器 (`src/passgen/`)** — 2,048 词 BIP-39 Diceware 助记词生成、视觉无歧义字符密码生成 (`--exclude-ambiguous`)、Hex/Base64/Base32 原始密码学随机字节生成、主种子确定性派生 (`--seed`, `--context`)、5 级熵强度评估与自动过期剪贴板守卫 (`svault keygen`)。
16. **统一结构化 JSON 输出 (`--json`)** — 全命令支持机读标准 JSON 响应 (`status`, `command`, 详细元数据, 字节大小, 指纹)，便于 CI/CD 与自动化脚本管道集成。
17. **容器密钥轮换 (`rotate`, `src/rotate.rs`)** — 在不解密为明文落盘的前提下，为 `.svault` 容器或隐写载体原子化更换盐值、Nonce 与主密码/Keyfile，支持切换 DPAPI 绑定 (`--dpapi`/`--no-dpapi`) 或清除策略 (`--clear-policy`)。
18. **目录完整性金丝雀探针 (`canary`, `src/canary.rs`)** — 生成并校验受 HMAC-SHA256 签名的 SHA-256 防篡改完整性清单 (`svault canary init` / `svault canary verify`)，提供异常变更报告与结构化 JSON。
19. **MP3 ID3v2 与音频帧隐写引擎 (`src/mp3/`)** — 在 MPEG Audio Layer III 文件中通过 ID3v2 PRIV 帧或 MPEG 帧间填充实现隐写嵌入，提供透明自动检测与诱饵保险库合理抗辩 (`svault embed-mp3` / `svault extract-mp3`)。
20. **FIDO2 / Windows Hello 硬件凭据绑定 (`src/hardware_token/`)** — 绑定物理 FIDO2 USB 密钥 (YubiKey 等) 或 Windows Hello 生物识别 (TPM 联动)。遵循 W3C WebAuthn 与 CTAP 2.1 PRF (HMAC-Secret) 规范将硬件机密混入 Argon2id 基础密钥，并以 ChaCha20-Poly1305 AAD 验证 `SVHW` 头部 (`svault fido2`)。
21. **后量子混合密钥封装 (`src/pq_kem/`)** — 经典 **X25519** ECDH + NIST **FIPS 203 ML-KEM-768** 双层量子抗性密钥封装，通过 HKDF-SHA256 派生对称密钥，生成 `SVPQ` v1 容器与 ASCII 装甲 (`svault kem keygen`, `svault kem seal`, `svault kem open`, `svault kem inspect`)。
22. **全链路内存主动清零 (`zeroize`)** — 敏感密钥调度表、平文明文缓冲区、Shamir 多项式系数、TOTP 密钥与 DPAPI 平文缓冲区在 Drop 时通过 `zeroize` 自动覆写清零。

</details>

---

## 🏛️ 存储与隐写架构

<details open>
<summary><b>🏛️ 存储与隐写架构</b></summary>
<br>

```text
  [ 主机密数据 ] ──▶ [ ChaCha20-Poly1305 + CSPRNG 填充 ] ──┐ (隐藏槽位)
                                                             │
  [ 诱饵有效载荷 ] ──▶ [ ChaCha20-Poly1305 加密 ]          ──┴─▶ SVLT v2 容器 (.svault)
                                                                    ├── 独立磁盘存储
                                                                    └── 隐写载体
                                                                          ├── PNG 图像 (.png)
                                                                          ├── WAV 音频 (.wav)
                                                                          ├── BMP 图像 (.bmp)
                                                                          └── MP3 音频 (.mp3)
```

</details>

---

## ⚡ 核心功能与安全保障

<details open>
<summary><b>⚡ 核心功能与安全保障</b></summary>
<br>

- **Argon2id + ChaCha20-Poly1305 AEAD** — 128 位随机盐、96 位随机 Nonce、域隔离 256 位密钥派生与 128 位 Poly1305 认证标签，篡改即拒绝解密。
- **自动过期剪贴板守卫 (`clip`)** — 安全凭证剪贴板转移与自动销毁引擎：
  - **原生 Win32 集成**: 直接调用 Windows 剪贴板 API (`OpenClipboard`, `EmptyClipboard`, `SetClipboardData`, `CloseClipboard`)，带 10 次重试退避。
  - **历史记录与云同步抑制**: 注入 Windows 10/11 隐私格式 (`CanIncludeInClipboardHistory`, `ExcludeClipboardContentFromMonitorProcessing`, `Clipboard Viewer Ignore`)，阻止进入 Win+V 历史记录或同步至微软云端。
  - **恒定时间指纹比对**: 无分支 SHA-256 比对 (`constant_time_eq_32`) 确保仅在剪贴板仍包含受保护机密时执行清理，保护用户随后复制的新内容。
  - **视觉倒计时与即时清除**: 动态终端进度条 (`[████████░░] 12s remaining`)、非阻塞 Enter 键即时清除与静默后台模式 (`--silent`)。
  - **深度命令集成**: `--clip` 与 `--clip-ttl <秒>` 选项无缝集成至 `decrypt`, `decrypt-decoy`, `extract`, `extract-wav`, `totp code` 等命令。
- **RFC 6238 TOTP 2FA 保险库 (`totp`)** — 加密多账户双因素认证引擎：
  - **零外部依赖**: 内置 Base32 (RFC 4648)、RFC 3174 SHA-1、RFC 2104 HMAC (SHA-1/256/512)，100% 通过官方标准测试向量。
  - **硬件绑定与 AEAD 保护**: 账户机密保存在经 Argon2id + ChaCha20-Poly1305 与 Windows DPAPI 双重加密的 `.svault` 容器中。
  - **Key URI 互操作性**: 完整支持标准 `otpauth://totp/[Issuer:]Account?...` URI 的解析与序列化。
  - **时序攻击防御**: 恒定时间验证 (`constant_time_eq`) 与可配置的时间容差窗口 ($\pm S$)。
  - **终端交互体验**: 彩色代码显示、剩余秒数进度条 (`[████████░░] 19s`) 与 `--json` 模式。
- **密码强度与熵审计器 (`audit`)** — 针对密码与隐写载体的深度安全审计：
  - **香农熵与字符池熵计算**: 计算每字节精确比特数 ($0.0 \le H \le 8.0$)、总位数与字符池空间熵 ($L \log_2 R$)。
  - **弱密码模式检测**: 检测连续字符 (`1234`, `abcd`)、重复字符 (`aaaa`)、键盘走线 (`qwerty`, `asdfgh`) 与 Leetspeak 字典匹配 (`p@ssw0rd`)。
  - **多模型破解时间预测**: 在线限制速率 (100次/秒)、离线 Argon2id ($10^3$次/秒) 及离线 GPU 集群 ($10^{10}$次/秒)。
  - **隐写载体深度分析**: 检查 PNG 块、`IEND` 后的尾部注入数据、WAV RIFF `svLt` 子块、16 位 PCM LSB 流及卡方 ($\chi^2$) 均匀性检验。
- **Shamir 门限秘密共享 ($M$-of-$N$ 密钥拆分)** — 在 $\text{GF}(256)$ 上将机密拆分为 $2 \le M \le N \le 255$ 份份额：
  - **恒定时间有限域运算**: 无分支 Peasant 乘法与费马小定理求逆 ($a^{-1} = a^{254}$)，消除基于查找表的侧信道漏洞。
  - **双层完整性验证**: 内嵌 SHA-256 机密摘要以防恶意篡改份额重构，每份份额配备 CRC-32 检测传输损坏。
  - **灵活序列化格式**: ASCII 装甲块 (`-----BEGIN SHADOW VAULT SHARE-----`)、单行紧凑字符串 (`SVLT-S1-...`) 与结构化 JSON。
- **合理抗辩双密码容器** — 在单一 `.svault` 容器中并存核心机密与诱饵数据：
  - **无缝解密**: `svault decrypt -p <passphrase>` 自动识别并解锁与所提供密码匹配的槽位。
  - **统计学不可区分的隐藏槽位**: 隐藏卷没有任何明文魔数或长度字段，末尾填充呈现最大的香农熵 (~8.0 bits/byte)。
  - **大小混淆填充 (`--padding <bytes>`)**: 注入显式 CSPRNG 随机填充或默认 256 字节对齐，防止文件大小侧信道分析。
- **硬件与会话绑定 (`--dpapi`)** — 利用 Windows DPAPI 封装密文，使密文与生成它的 Windows 用户配置文件绑定，离开当前登录会话即无法解密。
- **主动内存清零 (`zeroize`)** — 敏感密钥调度与明文缓冲区在 Drop 时通过带编译器屏障的内存清零安全擦除。
- **无损 PNG 隐写 (`embed` / `extract`)** — 在 `IEND` 前注入 `svLt` 辅助块并带完整 CRC-32 校验，支持诱饵保险库直接嵌入。
- **WAV 音频隐写 (`embed-wav` / `extract-wav`)** — 双模式 WAV 隐匿：
  - **RIFF 子块模式 (`--mode chunk`)**: 附加带有 CRC-32 的独立 `svLt` 元数据块。
  - **16 位 PCM LSB 模式 (`--lsb`)**: 微调 16 位样本最低有效位，听觉无失真且文件长度保持不变。
  - **自动识别**: `extract-wav` 自动检测并解包子块与 LSB 载体。
- **BMP 24 位像素 LSB 隐写 (`embed-bmp` / `extract-bmp`)**:
  - **行步长对齐填充保留**: 精确规避 4 字节行填充，仅在 R/G/B 色彩通道中嵌入数据，避免图像畸变。
  - **12 字节防篡改信封**: 封装为 `[svLt: 4B][len: 4B LE][payload: NB][crc32: 4B LE]`，具备恒定时间 CRC-32 校验。
  - **载体审计与隐写分析**: 深度集成 `svault audit` 以验证像素 LSB 完整性。
- **柯西 Reed-Solomon 纠错装甲 (`armor` / `dearmor` / `repair`)**:
  - **$\text{GF}(256)$ 柯西 MDS 编码**: 生成矩阵 $[I_K; A]$ 具备柯西元素 $A_{i, j} = \frac{1}{(K + i) \oplus j}$。任意 $K$ 块完好份额均可通过高斯消元完美恢复 $K+M$ 块全量数据。
  - **分条带 CRC-32 与全局 SHA-256 绑定**: 每个条带具备独立 CRC-32 定位损坏位置，整体有效载荷由 SHA-256 认证。
  - **自愈修复子命令 (`repair`)**: 自动重建受损条带并导出全新 `.svault.asc` 或直接提取为二进制 (`--binary`)。
  - **透明解装甲恢复**: 在 `dearmor` 过程中若检测到数据条带损坏，自动触发柯西 RS 纠错重构。
- **目录与多文件打包 (`pack-dir` / `unpack-dir`)**:
  - **`SVAR` 二进制架构**: 18 字节头部 (`SVAR` v1)、条目元数据、独立 SHA-256 摘要与 8 字节尾部校验码。
  - **路径穿越与 Zip Slip 防御**: 规范化为 `/` 相对路径，严厉拒绝 `..`、绝对/UNC 路径、冒号数据流 (ADS) 与保留设备名。
  - **解压炸弹防御**: 设定总包大小 (8 GiB)、单文件 (4 GiB)、条目数 (100,000) 与层级深度 (64) 上限。
- **通用载体容量估算 (`capacity`)** — 计算 `.bmp`, `.wav`, `.png`, `.mp3` 载体的总容量、净可用容量与隐写封装开销。
- **零知识头部检查 (`inspect`)** — 在不解密、不暴露隐藏槽大小的前提下查看容器版本、DPAPI 标志、诱饵标志与盐值。
- **时间锁与过期策略头部 (`policy`)**:
  - **认证策略头部 (`SVPO`)**: 28 字节标准二进制头部，包含创建时间、生效时间 (`not_before`)、过期时间 (`expires_at`)、说明文本及 CRC-32。
  - **AEAD AAD 紧密绑定**: 整个策略块作为 ChaCha20-Poly1305 的附加认证数据 (`aad`) 注入，篡改时间戳会导致 MAC 校验失败拒绝解密。
- **Keyfile + 密码双因素密钥派生 (`keyfile`)**:
  - **流式 64 KiB HMAC-SHA256**: 在常数内存缓冲区中流式预哈希任意大小的物理 Keyfile。
  - **密码学 2FA 与仅 Keyfile 模式**: 派生 256 位高熵种子注入 Argon2id。
- **分块流式加密 (`stream`)** — 以 $O(1)$ 常数内存加密数 GB 大文件，具备每块独立 Nonce 与 AAD 派生。
- **隐写载体差异对比报告 (`compare`)** — 评估图像 MSE/PSNR/MAE、音频 SNR/PSNR、结构块表与香农熵位移 $\Delta H$。
- **死人开关与自毁防御 (`guard`)** — 绑定防篡改账本，达到失败上限自动执行 3 阶段物理粉碎，支持超时自毁。
- **确定性与 CSPRNG 密码生成器 (`keygen`)** — BIP-39 助记词、无歧义密码、原始随机字节生成及主种子确定性派生。
- **交互式终端保险库 Shell (`repl`)** — 内存解密键值存储，支持直接修改、查询与带自动过期剪贴板保护。
- **3 阶段文件粉碎器 (`shred`)** — 执行 `0x00` ➔ `0xFF` ➔ CSPRNG 覆盖，阻断数据恢复。
- **单静态二进制** — 采用 `+crt-static`, LTO 与剥离符号编译，零外部运行时依赖。

</details>

---

## 🚀 快速开始与 CLI 工作流

<details open>
<summary><b>🚀 快速开始与 CLI 工作流（点击分类展开 / 折叠）</b></summary>
<br>

<details open>
<summary><b>🔐 1. 双层加密与合理抗辩诱饵保险库 (#1 - #6)</b></summary>
<br>

```bash
# 1. 使用主密码与 Windows DPAPI 硬件绑定加密文件
svault encrypt -i wallet-seed.txt -o wallet.svault -p "your-strong-passphrase" --dpapi

# 2. 加密包含真实机密与诱饵数据的合理抗辩保险库
svault encrypt -i classified.txt --decoy shopping-list.txt -o deniable.svault \
  -p "primary-secret-pass" --decoy-passphrase "decoy-harmless-pass" --padding 512

# 3. 使用诱饵密码解密（仅释放无害诱饵数据）
svault decrypt -i deniable.svault -o revealed.txt -p "decoy-harmless-pass"
# 使用主密码解密（还原真实机密）
svault decrypt -i deniable.svault -o restored.txt -p "primary-secret-pass"

# 4. 无需解密直接检查保险库元数据 (.svault, .png, .wav 或 .bmp)
svault inspect deniable.svault

# 5. 将双密码诱饵保险库直接无损隐写嵌入 PNG 图像
svault embed -c wallpaper.png -s classified.txt --decoy shopping-list.txt -o wallpaper-stego.png \
  -p "primary-secret-pass" --decoy-passphrase "decoy-harmless-pass"

# 6. 从 PNG 图像中提取机密（支持主密码或诱饵密码）
svault extract -c wallpaper-stego.png -o restored-seed.txt -p "primary-secret-pass"
svault extract -c wallpaper-stego.png -o decoy-seed.txt --decoy-passphrase "decoy-harmless-pass"
```

</details>

<details open>
<summary><b>🖼️ 2. 无损媒体隐写：PNG、WAV、BMP、MP3 与容量估算 (#7 - #13)</b></summary>
<br>

```bash
# 7. 在 WAV 音频文件中隐匿机密（RIFF 子块或 16 位 PCM LSB）
svault embed-wav -c track.wav -s classified.txt -o track-lsb.wav -p "primary-secret-pass" --lsb

# 8. 从 WAV 音频文件中提取并解密机密（自动检测子块或 LSB）
svault extract-wav -c track-lsb.wav -o restored-audio.txt -p "primary-secret-pass"

# 9. 估算媒体载体的可用隐写容量 (.bmp, .wav, .png 或 .mp3)
svault capacity landscape.bmp
svault capacity track.wav --json
svault capacity song.mp3

# 10. 通过像素 LSB 在 24 位 BMP 图像中隐匿机密
svault embed-bmp -c landscape.bmp -s classified.txt -o landscape-stego.bmp -p "primary-secret-pass"

# 11. 从 BMP 图像直接提取机密至自动过期剪贴板 (15秒后自动擦除)
svault extract-bmp -c landscape-stego.bmp -p "primary-secret-pass" --clip --clip-ttl 15

# 12. 在 MP3 音频中隐匿机密（ID3v2 PRIV 标签帧或帧间填充模式）
svault embed-mp3 -c song.mp3 -s classified.txt -o song-stego.mp3 -p "primary-secret-pass" --mode id3v2
svault embed-mp3 -c song.mp3 -s classified.txt -o song-frame.mp3 -p "primary-secret-pass" --mode frame

# 13. 从 MP3 音频文件中提取机密（自动识别模式）
svault extract-mp3 -c song-stego.mp3 -o restored-mp3.txt -p "primary-secret-pass"
```

</details>

<details open>
<summary><b>🧩 3. 安全文件粉碎、Shamir 门限秘密共享与熵审计 (#12 - #16)</b></summary>
<br>

```bash
# 12. 安全彻底粉碎原始明文文件（3 阶段覆盖）
svault shred classified.txt --passes 3

# 13. 将主恢复密钥拆分为 3-of-5 Shamir 门限份额
svault split -s "your-master-seed-or-secret" -m 3 -n 5 -o shares/share

# 14. 聚合任意 3 份份额重构原始机密
svault combine shares/share_1.share shares/share_3.share shares/share_5.share -o restored.txt

# 15. 深度审计密码强度、香农熵与暴力破解耗时估算
svault audit -p "Correct-Horse-Battery-Staple-2026!"

# 16. 审计隐写载体图像或容器的异常与隐藏有效载荷
svault audit wallpaper-stego.png --json
```

</details>

<details open>
<summary><b>⏱️ 4. RFC 6238 TOTP 2FA 保险库与自动过期剪贴板守卫 (#17 - #23)</b></summary>
<br>

```bash
# 17. 通过 Base32 密钥或 otpauth:// URI 添加 TOTP 2FA 凭据
svault totp add github --secret "JBSWY3DPEHPK3PXP" --issuer "GitHub" --vault totp.svault -p "vault-pass"
svault totp add --uri "otpauth://totp/Google:alice?secret=JBSWY3DPEHPK3PXP&issuer=Google" --vault totp.svault -p "vault-pass"

# 18. 生成实时 2FA 动态验证码（具备视觉倒计时进度条，支持 --json）
svault totp code github --vault totp.svault -p "vault-pass"
svault totp code github --vault totp.svault -p "vault-pass" --json

# 19. 基于时钟偏差窗口验证 OTP 验证码 (+/- 1 步长)
svault totp verify github 123456 --skew 1 --vault totp.svault -p "vault-pass"

# 20. 列出并导出 2FA 账户
svault totp list --vault totp.svault -p "vault-pass"
svault totp export github --vault totp.svault -p "vault-pass"

# 21. 将机密安全复制至剪贴板，设定 15 秒后自动销毁（支持静默模式）
svault clip copy "my-super-secret-password" --ttl 15
svault clip copy "my-super-secret-password" --ttl 15 --silent

# 22. 检查剪贴板状态及历史记录抑制元数据，或手动立即清空
svault clip status
svault clip clear

# 23. 直接解密至受保护剪贴板，不向终端回显且不向磁盘落盘
svault decrypt -i secret.svault -p "vault-pass" --clip --clip-ttl 30
svault totp code github --vault totp.svault -p "vault-pass" --clip --clip-ttl 15
```

</details>

<details open>
<summary><b>🛡️ 5. 柯西 Reed-Solomon 纠错装甲与目录打包 (#24 - #30)</b></summary>
<br>

```bash
# 24. 使用柯西 Reed-Solomon 校验条带对 .svault 容器进行 ASCII 装甲保护 (.svault.asc)
svault armor -i secret.svault -o secret.svault.asc -k 4 -m 2

# 25. 将 ASCII 装甲文件还原为原始 .svault 二进制容器
svault dearmor -i secret.svault.asc -o recovered.svault

# 26. 利用柯西 Reed-Solomon 校验奇偶条带自愈修复损坏的 .svault.asc 文件
svault repair -i corrupted.svault.asc -o repaired.svault.asc --json
svault repair -i corrupted.svault.asc -o direct_recovered.svault --binary

# 27. 检查与审计 ASCII 装甲容器条带状态与完整性
svault inspect secret.svault.asc
svault audit secret.svault.asc --json

# 28. 将整个目录树打包封入加密的 .svault 归档容器
svault pack-dir -i ./my_project -o project.svault -p "pack-passphrase" --list

# 29. 将目录直接打包嵌入隐写载体 (PNG, WAV, BMP, MP3) 或 ASCII 装甲
svault pack-dir -i ./my_project -o project.png -p "pack-passphrase" --carrier cover.png
svault pack-dir -i ./my_project -o project.svault.asc -p "pack-passphrase" --armor

# 30. 解包目录归档、检查清单或预先验证密码学摘要
svault unpack-dir -i project.svault -p "pack-passphrase" --list
svault unpack-dir -i project.svault -p "pack-passphrase" --verify-only
svault unpack-dir -i project.svault -o ./restored_project -p "pack-passphrase" --overwrite
```

</details>

<details open>
<summary><b>⏳ 6. 时间锁策略、USB Keyfile 与分块流式加密 (#31 - #42)</b></summary>
<br>

```bash
# 31. 加密带有时间锁托管策略的文件（指定未来时间前不可解密）
svault encrypt -i escrow.txt -o escrow.svault -p "vault-pass" --not-before "2026-12-31T00:00:00Z" --policy-desc "Year-End Escrow"

# 32. 加密带有自动过期策略的文件（2 小时后或特定 ISO 日期后失效）
svault encrypt -i token.txt -o token.svault -p "vault-pass" --expires-in 2h --policy-desc "Session Token"
svault encrypt -i doc.txt -o doc.svault -p "vault-pass" --expires-at "2026-10-15"

# 33. 无需解密直接检查策略元数据（文本与 JSON）
svault inspect escrow.svault
svault inspect escrow.svault --json

# 34. 指定参考基准时间测试解密
svault decrypt -i escrow.svault -o restored.txt -p "vault-pass" --at-time "2027-01-01"

# 35. 生成密码学 CSPRNG 硬件 USB Keyfile（默认 64 字节）
svault keyfile generate -o usb_token.key --bytes 64

# 36. 检查 Keyfile 指纹与香农熵（文本与 JSON）
svault keyfile inspect usb_token.key
svault keyfile inspect usb_token.key --json
svault keyfile fingerprint usb_token.key

# 37. 使用双因素 2FA (密码 + Keyfile) 进行加密与解密
svault encrypt -i secret.txt -o sealed.svault -p "master-pass" -k usb_token.key
svault decrypt -i sealed.svault -o restored.txt -p "master-pass" -k usb_token.key

# 38. 仅依赖 Keyfile 无密码加密
svault encrypt -i token.txt -o hardware.svault -k usb_token.key
svault decrypt -i hardware.svault -o restored.txt -k usb_token.key

# 39. 使用 Keyfile 2FA 打包与解包目录归档
svault pack-dir -i ./confidential -o archive.svault -p "pack-pass" -k usb_token.key
svault unpack-dir -i archive.svault -o ./unpacked -p "pack-pass" -k usb_token.key

# 40. 分块流式加密多 GB 超大文件（默认 4 MiB 分块或自定义）
svault stream encrypt -i large_dataset.iso -o large_dataset.svault -p "stream-pass"
svault encrypt -i database.backup -o db.svault -p "stream-pass" --stream --chunk-size 8M

# 41. 解密流式容器（自动识别 SVST 格式或使用 stream 子命令）
svault decrypt -i large_dataset.svault -o restored.iso -p "stream-pass"
svault stream decrypt -i db.svault -o restored_db.backup -p "stream-pass"

# 42. 无需解密检查流式容器元数据
svault stream inspect large_dataset.svault
svault inspect large_dataset.svault --json
```

</details>

<details open>
<summary><b>🚨 7. 隐写差异报告、死人自毁开关与密码生成器 (#43 - #53)</b></summary>
<br>

```bash
# 43. 对比原始载体与隐写载体（PNG, BMP, WAV 或二进制）
svault compare cover.bmp stego.bmp
svault compare cover.png stego.png --json
svault diff original.wav stego.wav --detailed

# 44. 为保险库部署 3 次密码错误自毁防御与死人开关
svault encrypt -i secret.txt -o guarded.svault -p "vault-pass" --max-attempts 3 --dead-man 7d --guard-companion

# 45. 直接为现有载体或容器装载自毁防御
svault guard arm -t stego.png --max-attempts 3 --companion
svault guard arm -t vault.svault --max-attempts 5 --dead-man 24h

# 46. 检查防御状态与剩余尝试次数（文本与 JSON）
svault guard status -t guarded.svault
svault guard status -t guarded.svault --json

# 47. 签到刷新死人开关期限或重置失败计数器
svault guard checkin -t guarded.svault --interval 30d
svault guard reset -t guarded.svault

# 48. 解除自毁防御或紧急触发多阶段彻底粉碎
svault guard disarm -t guarded.svault
svault guard trigger -t guarded.svault --force --passes 3

# 49. 生成 6 个词的 BIP-39 Diceware 恢复短语
svault keygen --words 6

# 50. 生成带数字与大写分隔符的自定义 Diceware
svault keygen --words 4 --separator "." --capitalize --number

# 51. 生成 24 位字符密码（去除视觉混淆字符，带熵评估）
svault keygen --length 24 --exclude-ambiguous --entropy

# 52. 基于主种子与服务上下文确定性派生密码
svault keygen --words 6 --seed "master-recovery-seed" --context "github-token"

# 53. 生成 32 字节原始密码学随机令牌并自动复制至剪贴板
svault keygen --bytes 32 --base64 --clip --clip-ttl 30
svault keygen --bytes 20 --base32 --json
```

</details>

<details open>
<summary><b>💻 8. 密钥轮换、金丝雀完整性与 REPL 交互 Shell (#54 - #63)</b></summary>
<br>

```bash
# 54. 使用新密码、新盐与新 Nonce 轮换更新容器密钥
svault rotate -i vault.svault -o rotated.svault -p "old-secret" -n "new-secret"

# 55. 原地原子化替换轮换容器或隐写载体
svault rotate -i vault.svault --in-place -p "old-secret" -n "new-secret"
svault rotate -i stego.bmp --in-place -p "old-pass" -n "new-pass"

# 56. 轮换隐写载体密钥 (PNG, WAV, BMP 或 ASCII 装甲)
svault rotate -i carrier.png -o rotated.png -p "old-pass" -n "new-pass"
svault rotate -i carrier.asc -o rotated.asc -p "old-pass" -n "new-pass"

# 57. 轮换时切换 DPAPI 硬件绑定或清除策略
svault rotate -i vault.svault -o dpapi_vault.svault -p "old-pass" -n "new-pass" --dpapi
svault rotate -i locked.svault -o unlocked.svault -p "old-pass" -n "new-pass" --clear-policy --json

# 58. 为目标目录初始化分离式金丝雀完整性清单
svault canary init -d ./vaults
svault canary init -d ./vaults -p "canary-auth-secret" --json

# 59. 校验金丝雀清单防范磁盘文件篡改
svault canary verify -d ./vaults
svault canary verify -d ./vaults -p "canary-auth-secret" --strict --json

# 60. 启动内存键值保险库交互式 REPL 终端 Shell
svault repl -v myvault.svault -p "session-pass"

# 61. 通过 --exec 非交互执行批处理 REPL 命令
svault repl -v myvault.svault -p "session-pass" --exec "set api_key sk_live_xyz --tag prod; set db_pass secret; save"

# 62. 直接查询机密并受自动过期剪贴板保护
svault repl -v myvault.svault -p "session-pass" --exec "get api_key --clip --clip-ttl 15"

# 63. 以只读模式启动 REPL 或导出键值为 JSON
svault repl -v myvault.svault -p "session-pass" --readonly --exec "list" --json
svault repl -v myvault.svault -p "session-pass" --exec "export ./backup.json; exit"
```

</details>

<details open>
<summary><b>🔑 9. FIDO2 / Windows Hello 硬件密钥凭据绑定 (#64 - #70)</b></summary>
<br>

```bash
# 64. 检查主机硬件令牌支持能力（Windows Hello, WebAuthn API, USB HID）
svault fido2 status
svault fido2 status --json

# 65. 注册 FIDO2 USB 密钥或 Windows Hello 凭据
svault fido2 enroll yubikey-5c --type usb --user alice --output ./yubikey.json
svault fido2 enroll hello-tpm --type hello --pin 849201 --json

# 66. 测试认证器断言并验证 PRF 派生指纹
svault fido2 test ./yubikey.json
svault fido2 test ./yubikey.json --json

# 67. 使用 FIDO2 硬件凭据绑定与主密码加密容器
svault encrypt -i secret.txt -o sealed.svault --fido2-cred ./yubikey.json -p "master-pass"

# 68. 使用已注册的硬件凭据解密容器
svault decrypt -i sealed.svault -o restored.txt --fido2-cred ./yubikey.json -p "master-pass"

# 69. 多因素 2FA: Keyfile + FIDO2 物理令牌（无需密码）
svault encrypt -i secret.txt -o mfa.svault -k usb_token.key --fido2-cred ./yubikey.json
svault decrypt -i mfa.svault -o restored.txt -k usb_token.key --fido2-cred ./yubikey.json

# 70. 轮换现有容器以添加或解除 FIDO2 硬件绑定
svault rotate -i sealed.svault --in-place -p "old-pass" -n "new-pass" --fido2 --fido2-cred ./yubikey.json
svault rotate -i sealed.svault --in-place -p "new-pass" -n "plain-pass" --no-fido2 --fido2-cred ./yubikey.json
```

</details>

<details open>
<summary><b>⚛️ 10. 后量子混合密钥封装 (X25519 + ML-KEM-768) (#71 - #74)</b></summary>
<br>

```bash
# 71. 生成后量子混合公私钥对 (X25519 + ML-KEM-768)
svault kem keygen -p recipient.pub -s recipient.key
svault kem keygen -p recipient.pub -s recipient.key --json

# 72. 使用接收方公钥封装机密文件（原生二进制或 ASCII 装甲）
svault kem seal -i classified.txt -o sealed.svault.pq -k recipient.pub
svault kem seal -i classified.txt -o sealed.asc -k recipient.pub --armor --json

# 73. 检查后量子容器元数据（临时公钥、ML-KEM 密文大小、CRC-32）
svault kem inspect -i sealed.svault.pq
svault kem inspect -i sealed.asc --json

# 74. 使用接收方私钥解封并解密后量子保险库
svault kem open -i sealed.svault.pq -o restored.txt -k recipient.key
svault kem open -i sealed.asc -o restored.txt -k recipient.key --json
```

</details>

</details>

---

## 🔒 内存安全与强化不变量

<details open>
<summary><b>🔒 内存安全与强化不变量</b></summary>
<br>

- **100% 内存安全 Rust 与常数时间密码运算**：核心密码路径无 `unsafe` 代码块，有限域多项式运算恒定时间执行，彻底消除基于时序的侧信道分析。
- **全链路内存主动清零**：敏感密钥调度表、平文明文缓冲区与 PRF 种子在 Drop 时由 `zeroize` 自动覆写清零。
- **硬件与会话绑定**：可选 Windows DPAPI 绑定，离开本机与当前登录会话即无法解密。
- **路径穿越与压缩炸弹防护**：采用严格规范化相对路径、严厉的 Zip Slip 校验与硬性内存分配上限。

</details>

---

## 📄 许可证与版权声明

<details open>
<summary><b>📄 许可证与版权声明</b></summary>
<br>

Copyright 2026 **GHSFS** ([https://github.com/GHSFS](https://github.com/GHSFS)).

本项目采用 **Apache License, Version 2.0** ([`LICENSE`](../../LICENSE)) 授权。依照 Apache-2.0 第 4(d) 条规定，任何派生作品与再分发版本均需完整保留 [`NOTICE`](../../NOTICE) 文件中的版权与致谢声明。

</details>
