<div align="center">

<p align="center">
  <a href="../../README.md">🇺🇸 English</a> · <a href="./ko.md">🇰🇷 한국어</a> · <a href="./zh-CN.md">🇨🇳 中文</a> · <a href="./es.md">🇪🇸 Español</a> · <a href="./hi.md">🇮🇳 हिन्दी</a><br />
  <a href="./ar.md">🇸🇦 العربية</a> · <strong>🇧🇷 Português</strong> · <a href="./ru.md">🇷🇺 Русский</a> · <a href="./fr.md">🇫🇷 Français</a> · <a href="./id.md">🇮🇩 Bahasa Indonesia</a>
</p>

# shadow-vault (`svault`)

> Cofre criptográfico com esteganografia de confiança zero e vinculação de hardware em camada dupla — oculte arquivos confidenciais dentro de arquivos comuns PNG/áudio, sele-os com Argon2id + ChaCha20-Poly1305 + Windows DPAPI, ou incorpore cofres de isca com negação plausível de senha dupla.

[![Build](https://github.com/GHSFS/shadow-vault/actions/workflows/build.yml/badge.svg)](https://github.com/GHSFS/shadow-vault/actions/workflows/build.yml)
[![Tests](https://github.com/GHSFS/shadow-vault/actions/workflows/test.yml/badge.svg)](https://github.com/GHSFS/shadow-vault/actions/workflows/test.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](../../LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20x64-0078D6)](#início-rápido)

</div>

---

### Visão Geral

O `shadow-vault` (`svault.exe`) é um utilitário criptográfico e esteganográfico em binário único sem dependências externas desenvolvido em Rust:

1. **Criptografia Autenticada de Camada Dupla (`SVLT` v1/v2)** — derivação de chaves via **Argon2id** + **ChaCha20-Poly1305** AEAD com proteção adicional via **Windows DPAPI (`CryptProtectData`)**.
2. **Negação Plausível e Cofres de Isca (`src/decoy.rs`)** — armazena um segredo real e uma carga inofensiva no mesmo arquivo; sob coerção, a senha de isca revela apenas os dados inofensivos.
3. **Esteganografia Sem Perdas em Mídias**:
   - **PNG**: inserção de bloco `svLt` antes de `IEND` com integridade CRC-32.
   - **WAV**: suporte a sub-blocos RIFF e substituição LSB em PCM de 16 bits.
   - **BMP**: modulação LSB em canais RGB de 24 bits com preservação de alinhamento de 4 bytes.
   - **MP3**: inserção em tags privadas ID3v2 `PRIV` ou preenchimento de quadros MPEG.
4. **Estimativa Universal de Capacidade (`capacity`)** — cálculo de capacidade em `.bmp`, `.wav`, `.png`, `.mp3`.
5. **Divisão de Segredos de Shamir (`M-de-N`, `src/shamir.rs`)** — aritmética em tempo constante em $\text{GF}(256)$ para divisão em $N$ cotas com limiar $M$.
6. **Auditor de Entropia e Força de Senhas (`src/audit.rs`)** — cálculo de entropia de Shannon e verificação de padrões vulneráveis.
7. **Cofre TOTP 2FA RFC 6238 (`src/totp.rs`)** — autenticador em dois fatores integrado com proteção contra ataques de temporização.
8. **Guarda de Área de Transferência com Expiração (`src/clipboard_guard.rs`)** — supressão de histórico do Windows 10/11 e limpeza com TTL.
9. **Armadura de Correção de Erros Cauchy Reed-Solomon (`src/armor.rs`)** — regeneração de dados íntegros a partir de $K$ blocos de $K+M$.
10. **Arquivo e Manifesto de Diretórios (`src/archive.rs`)** — proteção contra Zip Slip e integridade individual via SHA-256.
11. **Autenticação 2FA com Keyfile (`src/keyfile.rs`)** — integração de tokens USB físicos com HMAC-SHA256 pré-hash.
12. **Criptografia Contínua em Fluxo (`src/stream.rs`)** — blocos autenticados de 4 MiB para arquivos de múltiplos gigabytes em memória $O(1)$.
13. **Relatório de Diferença Visual e Estatística (`src/diff.rs`)** — cálculo de métricas MSE, PSNR, SNR e variação de entropia.
14. **Mecanismo de Homem Morto e Auto-Trituração (`src/guard.rs`)** — autodestruição com 3 passagens de sobrescrita após $K$ tentativas incorretas.
15. **Gerador BIP-39 e CSPRNG (`src/passgen/`)** — geração de frases mnemônicas de 2.048 palavras e tokens criptográficos.
16. **Modo JSON Estruturado Unificado (`--json`)** — integração completa com automações e pipelines CI/CD.
17. **Rotação de Chaves (`rotate`)** — substituição atômica de credenciais sem gravação de texto claro em disco.
18. **Canário de Integridade (`canary`)** — monitoramento de integridade e detecção de adulterações em árvores de arquivos.
19. **Vinculação de Hardware FIDO2 e Windows Hello (`src/hardware_token/`)** — integração com YubiKeys e biometria TPM via CTAP2 PRF.
20. **Encapsulamento Híbrido Pós-Quântico (`src/pq_kem/`)** — combinação de X25519 com NIST FIPS 203 ML-KEM-768.
21. **Zeroização Ativa de Memória (`zeroize`)** — destruição garantida de buffers sensíveis na memória.

### Início Rápido

```bash
# 1. Cifrar arquivo com senha e vinculação de hardware DPAPI
svault encrypt -i wallet-seed.txt -o wallet.svault -p "sua-senha-forte" --dpapi

# 2. Cifrar cofre de negação plausível com segredo real e isca
svault encrypt -i classified.txt --decoy shopping-list.txt -o deniable.svault \
  -p "senha-principal" --decoy-passphrase "senha-isca" --padding 512

# 3. Desbloquear com senha de isca
svault decrypt -i deniable.svault -o revealed.txt -p "senha-isca"

# 4. Inspecionar metadados sem descifrar
svault inspect deniable.svault

# 5. Ocultar cofre dentro de uma imagem PNG
svault embed -c wallpaper.png -s classified.txt --decoy shopping-list.txt -o wallpaper-stego.png \
  -p "senha-principal" --decoy-passphrase "senha-isca"

# 6. Extrair segredo real da imagem PNG
svault extract -c wallpaper-stego.png -o restored-seed.txt -p "senha-principal"
```

### Licença e Atribuição

Copyright 2026 **GHSFS** ([https://github.com/GHSFS](https://github.com/GHSFS)).

Distribuído sob a **Licença Apache 2.0** ([LICENSE](../../LICENSE)). Consulte o arquivo [NOTICE](../../NOTICE) para detalhes de atribuição.
