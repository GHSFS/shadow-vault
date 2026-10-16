<div align="center">

<p align="center">
  <a href="../../README.md">🇺🇸 English</a> · <a href="./ko.md">🇰🇷 한국어</a> · <a href="./zh-CN.md">🇨🇳 中文</a> · <a href="./es.md">🇪🇸 Español</a> · <a href="./hi.md">🇮🇳 हिन्दी</a><br />
  <a href="./ar.md">🇸🇦 العربية</a> · <strong>🇧🇷 Português</strong> · <a href="./ru.md">🇷🇺 Русский</a> · <a href="./fr.md">🇫🇷 Français</a> · <a href="./id.md">🇮🇩 Bahasa Indonesia</a>
</p>

# shadow-vault (`svault`)

> Esteganografia Zero-Trust e cofre criptografado vinculado ao hardware em camada dupla — oculte arquivos confidenciais dentro de mídias ordinárias de PNG/áudio, sele com Argon2id + ChaCha20-Poly1305 + Windows DPAPI, ou incorpore cofres chamariz com plausível desmentido por senha dupla.

[![Build](https://github.com/GHSFS/shadow-vault/actions/workflows/build.yml/badge.svg)](https://github.com/GHSFS/shadow-vault/actions/workflows/build.yml)
[![Tests](https://github.com/GHSFS/shadow-vault/actions/workflows/test.yml/badge.svg)](https://github.com/GHSFS/shadow-vault/actions/workflows/test.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](../../LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20x64-0078D6)](#-início-rápido-e-fluxos-de-trabalho-cli)

</div>

---

## 🛡️ Visão geral e capacidades principais

<details open>
<summary><b>🛡️ Visão geral e capacidades principais</b></summary>
<br>

`shadow-vault` (`svault.exe`) é um utilitário criptográfico e de esteganografia em binário único, escrito em Rust sem dependências externas, projetado para operadores que necessitam de proteção militar para arquivos de alto valor (frases semente, chaves privadas, credenciais e relatórios de pesquisa sigilosos):

1. **Criptografia autenticada de camada dupla (`SVLT` v1/v2)** — combina derivação de chave endurecida por memória **Argon2id** + **ChaCha20-Poly1305** AEAD com vinculação opcional de hardware e sessão de usuário do **Windows DPAPI (`CryptProtectData`)**. Mesmo que um invasor roube o arquivo `.svault` e a senha, um cofre protegido por DPAPI não pode ser descriptografado fora de sua conta de usuário do Windows.
2. **Plausível desmentido e cofres chamariz (`src/decoy.rs`)** — embute um segredo principal oculto (desbloqueado com a senha mestra) e uma carga chamariz inofensiva (desbloqueada com a senha chamariz) dentro de um único contêiner. Sob coerção, revelar a senha chamariz libera apenas os dados inofensivos, enquanto o compartimento principal permanece indistinguível de ruído aleatório uniforme (preenchimento CSPRNG e texto cifrado ChaCha20-Poly1305).
3. **Esteganografia sem perdas em mídias** — oculta contêineres criptografados em mídias comuns:
   - **Imagens PNG (`embed` / `extract`)**: injeta um bloco auxiliar privado `svLt` antes de `IEND` com somas de verificação CRC-32 IEEE 802.3 válidas (suporte a cofres chamariz diretos).
   - **Arquivos de áudio WAV (`embed-wav` / `extract-wav`)**: suporta sub-blocos RIFF/WAVE (`--mode chunk`) e substituição de bit menos significativo (LSB) em amostras de áudio PCM de 16 bits (`--lsb`) com validação CRC-32.
   - **Imagens BMP (`src/bmp.rs`)**: modula LSB em canais de pixel RGB não compactados de 24 bits, preservando o preenchimento de linha de 4 bytes e adicionando um envelope de segurança de 12 bytes (`svLt`, tamanho, carga, CRC-32).
   - **Arquivos de áudio MP3 (`src/mp3/`)**: oculta cargas em quadros de tags privadas ID3v2.3/ID3v2.4 (`PRIV`) ou no preenchimento entre quadros MPEG Audio Layer III com validação de sincronia, preservação de metadados e estimativa de capacidade.
4. **Estimativa universal de capacidade de suporte (`capacity`)** — avalia com precisão o tamanho total, a capacidade útil em bytes e a sobrecarga de esteganografia em suportes `.bmp`, `.wav`, `.png` e `.mp3` (`svault capacity <carrier> [--json]`).
5. **Divisão de segredo de Shamir (`M-of-N`, `src/shamir.rs`)** — aritmética de corpo finito $\text{GF}(256)$ em tempo constante sem ramificações condicionais. Divide chaves mestras de recuperação, senhas ou contêineres em $N$ partes, exigindo $M$ partes quaisquer para reconstrução (`svault split` / `svault combine`). Suporta texto blindado ASCII, strings compactas e JSON.
6. **Auditor de força de senha e entropia de suporte (`src/audit.rs`)** — calcula bits de entropia de Shannon por byte, diversidade de caracteres e detecta padrões vulneráveis (caracteres repetidos, sequências, caminhos no teclado, leetspeak). Audita blocos PNG, fluxos WAV RIFF/LSB, LSB de pixels BMP e contêineres `.svault` (`svault audit <target>` / `svault audit -p <passphrase>`).
7. **Cofre 2FA TOTP RFC 6238 (`src/totp.rs`)** — autenticador local de dois fatores criptografado sem dependências externas, selado dentro de contêineres `.svault`. Inclui Base32 (RFC 4648), RFC 3174 SHA-1, RFC 2104 HMAC (SHA-1/256/512), analisador de URI `otpauth://totp/...`, verificação em tempo constante e barra de contagem regressiva no terminal (`svault totp add`, `svault totp code`, `svault totp list`, `svault totp verify`).
8. **Protetor de área de transferência com autoexpiração (`src/clipboard_guard.rs`)** — copia credenciais com segurança para a área de transferência do Windows e as apaga após um TTL configurável (ex.: `--clip-ttl 15`). Injeta formatos de privacidade do Windows 10/11 para impedir histórico (Win + V) e sincronização em nuvem, com verificação de impressão digital SHA-256 em tempo constante (`constant_time_eq_32`).
9. **Armadura de correção de erros Cauchy Reed-Solomon (`src/armor.rs`)** — adiciona faixas de paridade e exportação/importação blindada ASCII `.svault.asc` para sobreviver a corrupções de bits ou falhas em canais de texto. Utiliza a matriz geradora de Cauchy $[I_K; A]$ em $\text{GF}(256)$ com propriedades MDS: QUAISQUER $K$ faixas intactas de $K+M$ reconstroem todos os dados originais (`svault repair`).
10. **Empacotamento de diretórios e manifesto multiaquivos (`src/archive.rs`)** — empacota árvores completas com normalização de caminhos relativos, proteção multicamada contra Zip Slip, defesa contra bombas de descompressão, manifestos SHA-256 e preservação de permissões em um contêiner `SVLT` lacrado (`svault pack-dir` / `svault unpack-dir`).
11. **Derivação de chave de dois fatores Keyfile + Senha (`src/keyfile.rs`)** — combina token USB ou arquivo chave externo (`--keyfile <path>`) com senhas via pré-hashing em fluxo HMAC-SHA256 de 64 KiB antes do Argon2id.
12. **Criptografia em fluxo fragmentado (`stream`)** — streaming autenticado de 4 MiB por bloco com memória constante $O(1)$ para arquivos gigantescos de vários gigabytes, proteção DPAPI e políticas de tempo.
13. **Relatório de diferença visual e estatística de esteganografia (`src/diff.rs`)** — avalia distorção visual (MSE, PSNR, MAE), distorção de áudio (SNR, PSNR) e desvio de entropia de Shannon $\Delta H$ (`svault compare <original> <stego>`).
14. **Interruptor Dead-Man e guarda de autodestruição por tentativas (`src/guard.rs`)** — livro-razão inviolável (`.guard`). Ao atingir $K$ falhas consecutivas ou término do prazo de inatividade, executa destruição criptográfica em 3 etapas (0x00, 0xFF, CSPRNG) e apaga o arquivo.
15. **Gerador determinístico e CSPRNG de senhas (`src/passgen/`)** — Diceware BIP-39 de 2.048 palavras, senhas com exclusão de caracteres ambíguos (`--exclude-ambiguous`), bytes aleatórios e semente mestre (`svault keygen`).
16. **Saída JSON estruturada unificada (`--json`)** — comandos com suporte a respostas padronizadas em JSON para scripts e automações CI/CD.
17. **Rotação de chaves de contêiner (`rotate`, `src/rotate.rs`)** — recifra contêineres e suportes com novo sal, Nonce e senhas/arquivos-chave de maneira atômica e segura.
18. **Manifesto canário de integridade desacoplado (`canary`, `src/canary.rs`)** — cria e verifica listas de controle SHA-256 assinadas com HMAC-SHA256 para monitorar diretórios.
19. **Motor de esteganografia MP3 ID3v2 e quadros de áudio (`src/mp3/`)** — oculta dados em arquivos MP3 com detecção transparente e desmentido plausível.
20. **Vinculação de credenciais de hardware FIDO2 / Windows Hello (`src/hardware_token/`)** — vincula chaves de criptografia a chaves físicas USB FIDO2 ou biometria TPM (`svault fido2`).
21. **Encapsulamento de chaves híbrido pós-quântico (`src/pq_kem/`)** — selamento assimétrico de dupla camada combinando X25519 clássico e NIST FIPS 203 ML-KEM-768 (`svault kem`).
22. **Zerar memória proativamente (`zeroize`)** — limpa buffers de chaves e texto simples da memória com 0x00 imediatamente após o uso.

</details>

---

## 🏛️ Arquitetura de armazenamento e esteganografia

<details open>
<summary><b>🏛️ Arquitetura de armazenamento e esteganografia</b></summary>
<br>

```text
  [ Segredo Principal ] ──▶ [ ChaCha20-Poly1305 + Preenchimento CSPRNG ] ──┐ (Compartimento Oculto)
                                                                            │
  [ Carga Chamariz ]    ──▶ [ Criptografia ChaCha20-Poly1305 ]           ──┴─▶ Contêiner SVLT v2 (.svault)
                                                                                  ├── Armazenamento direto em disco
                                                                                  └── Suporte Esteganográfico
                                                                                        ├── Imagem PNG (.png)
                                                                                        ├── Áudio WAV (.wav)
                                                                                        ├── Imagem BMP (.bmp)
                                                                                        └── Áudio MP3 (.mp3)
```

</details>

---

## ⚡ Recursos fundamentais e garantias de segurança

<details open>
<summary><b>⚡ Recursos fundamentais e garantias de segurança</b></summary>
<br>

- **Argon2id + ChaCha20-Poly1305 AEAD** — sal aleatório de 128 bits, Nonce aleatório de 96 bits, derivação de chave de 256 bits com separação de domínios e tag Poly1305 de 128 bits.
- **Protetor de área de transferência com autoexpiração (`clip`)**:
  - **Chamadas Win32 nativas**: interação direta com APIs do Windows com 10 tentativas com recuo.
  - **Bloqueio de histórico e nuvem**: define formatos de privacidade do Windows 10/11 para impedir histórico (Win + V) ou envio à nuvem da Microsoft.
  - **Comparação em tempo constante**: comparação SHA-256 (`constant_time_eq_32`) para evitar sobrescrever dados novos do usuário.
  - **Contagem regressiva no terminal**: barra visual (`[████████░░] 12s remaining`), tecla Enter para limpeza instantânea e modo silencioso (`--silent`).
  - **Integração direta**: `--clip` e `--clip-ttl <seg>` disponíveis em `decrypt`, `extract`, `totp code`, etc.
- **Cofre 2FA TOTP RFC 6238 (`totp`)**:
  - **Zero dependências externas**: Base32, SHA-1 e HMAC com 100% de testes aprovados.
  - **Proteção por hardware e AEAD**: armazenamento em contêineres `.svault` protegidos por Argon2id e DPAPI.
  - **Total interoperabilidade**: suporte a URIs `otpauth://totp/...`.
  - **Verificação em tempo constante**: proteção contra ataques de temporização e janela de tolerância ($\pm S$).
- **Auditor de força de senhas e entropia (`audit`)**:
  - **Cálculo de entropia de Shannon**: $0.0 \le H \le 8.0$ bits por byte e tamanho de espaço de chaves.
  - **Detecção de vulnerabilidades**: repetições, sequências, teclado e termos comuns.
  - **Previsão de tempo para quebra**: modelos online (100/s), Argon2id offline ($10^3$/s) e clusters GPU ($10^{10}$/s).
  - **Esteganálise de suportes**: testes de conformidade e uniformidade Chi-quadrado ($\chi^2$).
- **Divisão de segredo de Shamir ($M$-de-$N$)**:
  - **Aritmética de corpo constante**: multiplicação sem desvios e inversão de Fermat ($a^{-1} = a^{254}$) em $\text{GF}(256)$.
  - **Integridade dupla**: resumo SHA-256 integrado e CRC-32 por parte.
- **Contêineres com plausível desmentido por senha dupla**:
  - **Descriptografia transparente**: desbloqueia o compartimento exato associado à senha informada.
  - **Compartimento oculto indistinguível**: sem cabeçalhos óbvios; cauda com máxima entropía (~8.0 bits/byte).
  - **Ofuscação de tamanho (`--padding <bytes>`)**: preenchimento aleatório CSPRNG.
- **Vinculação de hardware / sessão (`--dpapi`)** — texto cifrado vinculado ao perfil do usuário no Windows.
- **Zerar memória proativamente (`zeroize`)** — sobrescreve buffers com zeros ao sair de escopo.
- **Esteganografia PNG sem perdas (`embed` / `extract`)** — fragmento `svLt` com CRC-32 e suporte a chamariz.
- **Esteganografia em áudio WAV (`embed-wav` / `extract-wav`)**:
  - **Modo sub-bloco RIFF (`--mode chunk`)**: metadados `svLt` com CRC-32.
  - **Modo LSB PCM 16 bits (`--lsb`)**: altera o bit menos significativo de amostras sem impacto acústico.
- **Esteganografia LSB em pixels BMP 24 bits (`embed-bmp` / `extract-bmp`)**:
  - **Preservação de alinhamento de linha**: mantém 4 bytes de preenchimento e oculta em canais R, G, B.
  - **Envelope de 12 bytes seguro**: `[svLt: 4B][len: 4B LE][payload: NB][crc32: 4B LE]`.
- **Armadura de correção de erros Cauchy Reed-Solomon (`armor` / `dearmor` / `repair`)**:
  - **MDS sobre $\text{GF}(256)$**: matriz $[I_K; A]$. Qualquer conjunto de $K$ faixas intactas reconstrói tudo.
  - **CRC-32 por faixa e SHA-256 geral**: localização precisa de falhas e autenticação do contêiner.
  - **Autorreparo transparente**: reconstrução em `repair` e recuperação automática em `dearmor`.
- **Empacotamento de diretórios (`pack-dir` / `unpack-dir`)**:
  - **Formato binário `SVAR`**: cabeçalho de 18 bytes, hashes individuais SHA-256 e soma CRC-32.
  - **Prevenção contra Zip Slip**: rejeita caminhos absolutos, `..` e dispositivos reservados do Windows.
  - **Limite contra bombas de descompressão**: teto de 8 GiB total e 4 GiB por arquivo.
- **Estimativa de capacidade de suporte (`capacity`)** — cálculo de carga útil líquida em `.bmp`, `.wav`, `.png`, `.mp3`.
- **Inspeção de cabeçalho com zero conhecimento (`inspect`)** — leitura de versão, sal e flags sem descriptografar.
- **Políticas temporais de bloqueio e expiração (`policy`)**:
  - **Cabeçalho autenticado (`SVPO`)**: 28 bytes canônicos com carimbos e descrição.
  - **Vinculado a AAD no AEAD**: qualquer alteração de prazo quebra o Poly1305.
- **Arquivo-chave + Senha (`keyfile`)** — buffer de 64 KiB para chaves USB com derivação de 256 bits para Argon2id.
- **Criptografia em fluxo (`stream`)** — memória constante $O(1)$ para arquivos com múltiplos gigabytes.
- **Relatório de diferenças estego (`compare`)** — métricas MSE/PSNR/MAE, SNR de áudio e desvio de entropia $\Delta H$.
- **Autodestruição e Dead-Man Switch (`guard`)** — 3 etapas de destruição em falhas consecutivas ou inatividade.
- **Gerador determinístico de senhas (`keygen`)** — Diceware BIP-39, senhas sem ambiguidades e tokens aleatórios.
- **Terminal interativo REPL (`repl`)** — gerenciamento de chaves-valores em memória com proteção de portapapeles.
- **Destruidor seguro de arquivos (`shred`)** — regravação em 3 etapas antes da exclusão.
- **Binário estático exclusivo** — sem dependências externas.

</details>

---

## 🚀 Início rápido e fluxos de trabalho CLI

<details open>
<summary><b>🚀 Início rápido e fluxos de trabalho CLI (Clique na categoria para expandir / recolher)</b></summary>
<br>

<details open>
<summary><b>🔐 1. Criptografia em camada dupla e cofres chamariz com plausível desmentido (#1 - #6)</b></summary>
<br>

```bash
# 1. Criptografar arquivo com senha e vinculação de hardware Windows DPAPI
svault encrypt -i wallet-seed.txt -o wallet.svault -p "your-strong-passphrase" --dpapi

# 2. Criptografar cofre com desmentido plausível contendo o segredo real e dados chamariz
svault encrypt -i classified.txt --decoy shopping-list.txt -o deniable.svault \
  -p "primary-secret-pass" --decoy-passphrase "decoy-harmless-pass" --padding 512

# 3. Descriptografar contêiner plausível (a senha chamariz revela apenas os dados inofensivos)
svault decrypt -i deniable.svault -o revealed.txt -p "decoy-harmless-pass"
# A senha principal recupera o segredo real completo
svault decrypt -i deniable.svault -o restored.txt -p "primary-secret-pass"

# 4. Inspecionar metadados do cofre sem descriptografar (.svault, .png, .wav ou .bmp)
svault inspect deniable.svault

# 5. Ocultar cofre chamariz de dupla senha diretamente dentro de imagem PNG
svault embed -c wallpaper.png -s classified.txt --decoy shopping-list.txt -o wallpaper-stego.png \
  -p "primary-secret-pass" --decoy-passphrase "decoy-harmless-pass"

# 6. Extrair segredo de imagem PNG (com a senha principal ou senha chamariz)
svault extract -c wallpaper-stego.png -o restored-seed.txt -p "primary-secret-pass"
svault extract -c wallpaper-stego.png -o decoy-seed.txt --decoy-passphrase "decoy-harmless-pass"
```

</details>

<details open>
<summary><b>🖼️ 2. Esteganografia sem perdas em mídias: PNG, WAV, BMP, MP3 e capacidade (#7 - #13)</b></summary>
<br>

```bash
# 7. Ocultar segredo dentro de arquivo de áudio WAV (sub-bloco RIFF ou PCM LSB 16 bits)
svault embed-wav -c track.wav -s classified.txt -o track-lsb.wav -p "primary-secret-pass" --lsb

# 8. Extrair e descriptografar segredo de arquivo WAV (autodetecção)
svault extract-wav -c track-lsb.wav -o restored-audio.txt -p "primary-secret-pass"

# 9. Estimar capacidade útil de suporte para esteganografia (.bmp, .wav, .png ou .mp3)
svault capacity landscape.bmp
svault capacity track.wav --json
svault capacity song.mp3

# 10. Ocultar segredo em imagem BMP de 24 bits por esteganografia LSB em pixels
svault embed-bmp -c landscape.bmp -s classified.txt -o landscape-stego.bmp -p "primary-secret-pass"

# 11. Extrair segredo de imagem BMP diretamente para área de transferência temporária (15s)
svault extract-bmp -c landscape-stego.bmp -p "primary-secret-pass" --clip --clip-ttl 15

# 12. Ocultar segredo em arquivo de áudio MP3 (tag ID3v2 PRIV ou preenchimento de quadros)
svault embed-mp3 -c song.mp3 -s classified.txt -o song-stego.mp3 -p "primary-secret-pass" --mode id3v2
svault embed-mp3 -c song.mp3 -s classified.txt -o song-frame.mp3 -p "primary-secret-pass" --mode frame

# 13. Extrair segredo de arquivo de áudio MP3 (reconhecimento automático de modo)
svault extract-mp3 -c song-stego.mp3 -o restored-mp3.txt -p "primary-secret-pass"
```

</details>

<details open>
<summary><b>🧩 3. Destruição segura, divisão de Shamir e auditoria de entropia (#12 - #16)</b></summary>
<br>

```bash
# 12. Destruir arquivo original em texto simples com segurança (3 passagens)
svault shred classified.txt --passes 3

# 13. Dividir chave mestra de recuperação em 3-de-5 partes de Shamir
svault split -s "your-master-seed-or-secret" -m 3 -n 5 -o shares/share

# 14. Combinar 3 partes quaisquer para reconstruir o segredo original
svault combine shares/share_1.share shares/share_3.share shares/share_5.share -o restored.txt

# 15. Auditar força de senha, entropia de Shannon e estimativa de tempo para quebra
svault audit -p "Correct-Horse-Battery-Staple-2026!"

# 16. Auditar imagem de suporte estego ou contêiner em busca de anomalias
svault audit wallpaper-stego.png --json
```

</details>

<details open>
<summary><b>⏱️ 4. Cofre 2FA TOTP RFC 6238 e proteção de área de transferência (#17 - #23)</b></summary>
<br>

```bash
# 17. Adicionar credencial 2FA TOTP via chave Base32 ou URI otpauth://
svault totp add github --secret "JBSWY3DPEHPK3PXP" --issuer "GitHub" --vault totp.svault -p "vault-pass"
svault totp add --uri "otpauth://totp/Google:alice?secret=JBSWY3DPEHPK3PXP&issuer=Google" --vault totp.svault -p "vault-pass"

# 18. Gerar código OTP 2FA com barra visual de contagem regressiva (ou --json)
svault totp code github --vault totp.svault -p "vault-pass"
svault totp code github --vault totp.svault -p "vault-pass" --json

# 19. Verificar código OTP com janela de tolerância (+/- 1 passo)
svault totp verify github 123456 --skew 1 --vault totp.svault -p "vault-pass"

# 20. Listar e exportar contas 2FA
svault totp list --vault totp.svault -p "vault-pass"
svault totp export github --vault totp.svault -p "vault-pass"

# 21. Copiar segredo para área de transferência com autoexpiração em 15s (ou silencioso)
svault clip copy "my-super-secret-password" --ttl 15
svault clip copy "my-super-secret-password" --ttl 15 --silent

# 22. Verificar status da área de transferência e dados de privacidade, ou limpar manualmente
svault clip status
svault clip clear

# 23. Descriptografar diretamente para a área de transferência sem exibir no terminal ou disco
svault decrypt -i secret.svault -p "vault-pass" --clip --clip-ttl 30
svault totp code github --vault totp.svault -p "vault-pass" --clip --clip-ttl 15
```

</details>

<details open>
<summary><b>🛡️ 5. Armadura Cauchy Reed-Solomon e empacotamento de diretórios (#24 - #30)</b></summary>
<br>

```bash
# 24. Proteger contêiner .svault com armadura ASCII e paridade Cauchy Reed-Solomon (.svault.asc)
svault armor -i secret.svault -o secret.svault.asc -k 4 -m 2

# 25. Converter arquivo blindado ASCII de volta para contêiner binário .svault original
svault dearmor -i secret.svault.asc -o recovered.svault

# 26. Reparar arquivo .svault.asc corrompido utilizando paridade Cauchy Reed-Solomon
svault repair -i corrupted.svault.asc -o repaired.svault.asc --json
svault repair -i corrupted.svault.asc -o direct_recovered.svault --binary

# 27. Inspecionar e auditar integridade de faixas em contêiner blindado ASCII
svault inspect secret.svault.asc
svault audit secret.svault.asc --json

# 28. Empacotar árvore completa de diretórios em contêiner .svault criptografado
svault pack-dir -i ./my_project -o project.svault -p "pack-passphrase" --list

# 29. Empacotar diretamente em suporte estego (PNG, WAV, BMP, MP3) ou armadura ASCII
svault pack-dir -i ./my_project -o project.png -p "pack-passphrase" --carrier cover.png
svault pack-dir -i ./my_project -o project.svault.asc -p "pack-passphrase" --armor

# 30. Desempacotar diretório, listar manifesto ou pré-validar resumos criptográficos
svault unpack-dir -i project.svault -p "pack-passphrase" --list
svault unpack-dir -i project.svault -p "pack-passphrase" --verify-only
svault unpack-dir -i project.svault -o ./restored_project -p "pack-passphrase" --overwrite
```

</details>

<details open>
<summary><b>⏳ 6. Políticas temporais, chaves USB Keyfile e streaming fragmentado (#31 - #42)</b></summary>
<br>

```bash
# 31. Criptografar com política de bloqueio temporal (não abre antes da data futura)
svault encrypt -i escrow.txt -o escrow.svault -p "vault-pass" --not-before "2026-12-31T00:00:00Z" --policy-desc "Year-End Escrow"

# 32. Criptografar com política de autoexpiração (expira em 2 horas ou data ISO específica)
svault encrypt -i token.txt -o token.svault -p "vault-pass" --expires-in 2h --policy-desc "Session Token"
svault encrypt -i doc.txt -o doc.svault -p "vault-pass" --expires-at "2026-10-15"

# 33. Inspecionar metadados de políticas sem descriptografar (texto e JSON)
svault inspect escrow.svault
svault inspect escrow.svault --json

# 34. Testar descriptografia contra marcação de tempo de referência explícita
svault decrypt -i escrow.svault -o restored.txt -p "vault-pass" --at-time "2027-01-01"

# 35. Gerar arquivo-chave criptográfico USB (CSPRNG, padrão 64 bytes)
svault keyfile generate -o usb_token.key --bytes 64

# 36. Inspecionar impressão digital e entropia de Shannon da chave USB (texto e JSON)
svault keyfile inspect usb_token.key
svault keyfile inspect usb_token.key --json
svault keyfile fingerprint usb_token.key

# 37. Criptografar e descriptografar com dois fatores 2FA (Senha + Arquivo-chave)
svault encrypt -i secret.txt -o sealed.svault -p "master-pass" -k usb_token.key
svault decrypt -i sealed.svault -o restored.txt -p "master-pass" -k usb_token.key

# 38. Criptografia exclusiva com arquivo-chave sem senha
svault encrypt -i token.txt -o hardware.svault -k usb_token.key
svault decrypt -i hardware.svault -o restored.txt -k usb_token.key

# 39. Empacotar diretório em cofre criptografado com 2FA de arquivo-chave
svault pack-dir -i ./confidential -o archive.svault -p "pack-pass" -k usb_token.key
svault unpack-dir -i archive.svault -o ./unpacked -p "pack-pass" -k usb_token.key

# 40. Criptografar arquivos de vários gigabytes com streaming fragmentado (blocos de 4 MiB)
svault stream encrypt -i large_dataset.iso -o large_dataset.svault -p "stream-pass"
svault encrypt -i database.backup -o db.svault -p "stream-pass" --stream --chunk-size 8M

# 41. Descriptografar contêiner em fluxo (reconhece formato SVST ou via comando stream)
svault decrypt -i large_dataset.svault -o restored.iso -p "stream-pass"
svault stream decrypt -i db.svault -o restored_db.backup -p "stream-pass"

# 42. Inspecionar metadados de contêiner em fluxo sem descriptografar
svault stream inspect large_dataset.svault
svault stream inspect large_dataset.svault --json
```

</details>

<details open>
<summary><b>🚨 7. Relatórios de diferenças estego, guarda de autodestruição e senhas (#43 - #53)</b></summary>
<br>

```bash
# 43. Comparar suporte original com suporte esteganográfico (PNG, BMP, WAV ou binário)
svault compare cover.bmp stego.bmp
svault compare cover.png stego.png --json
svault diff original.wav stego.wav --detailed

# 44. Armar cofre com guarda de autodestruição para 3 tentativas e interruptor dead-man
svault encrypt -i secret.txt -o guarded.svault -p "vault-pass" --max-attempts 3 --dead-man 7d --guard-companion

# 45. Armar diretamente um suporte ou contêiner existente
svault guard arm -t stego.png --max-attempts 3 --companion
svault guard arm -t vault.svault --max-attempts 5 --dead-man 24h

# 46. Inspecionar status da guarda e tentativas restantes (texto e JSON)
svault guard status -t guarded.svault
svault guard status -t guarded.svault --json

# 47. Fazer check-in para estender prazo do interruptor dead-man ou zerar contador de erros
svault guard checkin -t guarded.svault --interval 30d
svault guard reset -t guarded.svault

# 48. Desarmar a guarda ou disparar destruição imediata de emergência
svault guard disarm -t guarded.svault
svault guard trigger -t guarded.svault --force --passes 3

# 49. Gerar frase de recuperação Diceware BIP-39 de 6 palavras
svault keygen --words 6

# 50. Gerar Diceware customizado com números e letras maiúsculas
svault keygen --words 4 --separator "." --capitalize --number

# 51. Gerar senha de 24 caracteres com filtro de ambiguidade e análise de entropia
svault keygen --length 24 --exclude-ambiguous --entropy

# 52. Derivação determinística de senha a partir de semente mestre e contexto de serviço
svault keygen --words 6 --seed "master-recovery-seed" --context "github-token"

# 53. Gerar token criptográfico aleatório de 32 bytes e copiar para área de transferência
svault keygen --bytes 32 --base64 --clip --clip-ttl 30
svault keygen --bytes 20 --base32 --json
```

</details>

<details open>
<summary><b>💻 8. Rotação de chaves, integridade canário e shell interativo REPL (#54 - #63)</b></summary>
<br>

```bash
# 54. Rotacionar chaves de contêiner com nova senha, sal e Nonce inéditos
svault rotate -i vault.svault -o rotated.svault -p "old-secret" -n "new-secret"

# 55. Rotacionar contêiner ou suporte in-place de forma atômica
svault rotate -i vault.svault --in-place -p "old-secret" -n "new-secret"
svault rotate -i stego.bmp --in-place -p "old-pass" -n "new-pass"

# 56. Rotacionar credenciais em suporte estego (PNG, WAV, BMP ou armadura ASCII)
svault rotate -i carrier.png -o rotated.png -p "old-pass" -n "new-pass"
svault rotate -i carrier.asc -o rotated.asc -p "old-pass" -n "new-pass"

# 57. Rotacionar alterando vinculação de hardware DPAPI ou limpando políticas
svault rotate -i vault.svault -o dpapi_vault.svault -p "old-pass" -n "new-pass" --dpapi
svault rotate -i locked.svault -o unlocked.svault -p "old-pass" -n "new-pass" --clear-policy --json

# 58. Inicializar manifesto canário de integridade desacoplado para diretório alvo
svault canary init -d ./vaults
svault canary init -d ./vaults -p "canary-auth-secret" --json

# 59. Verificar integridade canário contra alterações de arquivos em disco
svault canary verify -d ./vaults
svault canary verify -d ./vaults -p "canary-auth-secret" --strict --json

# 60. Iniciar shell interativo REPL de cofre chave-valor em memória
svault repl -v myvault.svault -p "session-pass"

# 61. Executar comandos REPL em lote de modo não interativo com --exec
svault repl -v myvault.svault -p "session-pass" --exec "set api_key sk_live_xyz --tag prod; set db_pass secret; save"

# 62. Consultar segredo diretamente protegido por área de transferência temporária
svault repl -v myvault.svault -p "session-pass" --exec "get api_key --clip --clip-ttl 15"

# 63. Abrir REPL em modo somente leitura ou exportar entradas para JSON
svault repl -v myvault.svault -p "session-pass" --readonly --exec "list" --json
svault repl -v myvault.svault -p "session-pass" --exec "export ./backup.json; exit"
```

</details>

<details open>
<summary><b>🔑 9. Vinculação de credenciais de chaves FIDO2 / Windows Hello (#64 - #70)</b></summary>
<br>

```bash
# 64. Inspecionar recursos de hardware da plataforma (Windows Hello, WebAuthn API, USB HID)
svault fido2 status
svault fido2 status --json

# 65. Registrar chave USB FIDO2 ou credencial do Windows Hello
svault fido2 enroll yubikey-5c --type usb --user alice --output ./yubikey.json
svault fido2 enroll hello-tpm --type hello --pin 849201 --json

# 66. Testar asserção do autenticador e verificar impressão de derivação PRF
svault fido2 test ./yubikey.json
svault fido2 test ./yubikey.json --json

# 67. Criptografar contêiner vinculando credencial de hardware FIDO2 + senha
svault encrypt -i secret.txt -o sealed.svault --fido2-cred ./yubikey.json -p "master-pass"

# 68. Descriptografar contêiner utilizando a credencial de hardware registrada
svault decrypt -i sealed.svault -o restored.txt --fido2-cred ./yubikey.json -p "master-pass"

# 69. Autenticação multifator 2FA: Arquivo-chave + token físico FIDO2 (sem senha)
svault encrypt -i secret.txt -o mfa.svault -k usb_token.key --fido2-cred ./yubikey.json
svault decrypt -i mfa.svault -o restored.txt -k usb_token.key --fido2-cred ./yubikey.json

# 70. Rotacionar contêiner existente para adicionar ou desvincular credencial FIDO2
svault rotate -i sealed.svault --in-place -p "old-pass" -n "new-pass" --fido2 --fido2-cred ./yubikey.json
svault rotate -i sealed.svault --in-place -p "new-pass" -n "plain-pass" --no-fido2 --fido2-cred ./yubikey.json
```

</details>

<details open>
<summary><b>⚛️ 10. Encapsulamento de chaves pós-quântico (X25519 + ML-KEM-768) (#71 - #74)</b></summary>
<br>

```bash
# 71. Gerar par de chaves híbrido pós-quântico (X25519 + ML-KEM-768)
svault kem keygen -p recipient.pub -s recipient.key
svault kem keygen -p recipient.pub -s recipient.key --json

# 72. Selar arquivo confidencial para a chave pública do destinatário (binário ou ASCII)
svault kem seal -i classified.txt -o sealed.svault.pq -k recipient.pub
svault kem seal -i classified.txt -o sealed.asc -k recipient.pub --armor --json

# 73. Inspecionar metadados de contêiner pós-quântico (chave efêmera, tamanho do texto cifrado, CRC-32)
svault kem inspect -i sealed.svault.pq
svault kem inspect -i sealed.asc --json

# 74. Abrir e descriptografar cofre pós-quântico com a chave privada do destinatário
svault kem open -i sealed.svault.pq -o restored.txt -k recipient.key
svault kem open -i sealed.asc -o restored.txt -k recipient.key --json
```

</details>

</details>

---

## 🔒 Segurança de memória e invariantes de proteção

<details open>
<summary><b>🔒 Segurança de memória e invariantes de proteção</b></summary>
<br>

- **100% Rust seguro e criptografia em tempo constante**: Zero blocos `unsafe` nos fluxos de dados sensíveis; aritmética de corpos de Galois sem desvios para banir ataques temporais de canal lateral.
- **Zerar memória ativamente**: Búferes de chaves intermediárias, texto simples e sementes PRF acionam sobrescrita de memória protegida contra otimizações do compilador no Drop via `zeroize`.
- **Vinculação a perfil de hardware**: O encapsulamento opcional por Windows DPAPI garante que os dados cifrados não possam ser lidos fora da máquina e da sessão de usuário que os gerou.
- **Defesas contra Zip Slip e bombas de descompressão**: Caminhos relativos canônicos, verificações rígidas e limites estritos de alocação de memória impedem o esgotamento de recursos do sistema.

</details>

---

## 📄 Licença e atribuição

<details open>
<summary><b>📄 Licença e atribuição</b></summary>
<br>

Copyright 2026 **GHSFS** ([https://github.com/GHSFS](https://github.com/GHSFS)).

Distribuído sob a **Licença Apache, Versão 2.0** ([`LICENSE`](../../LICENSE)).
De acordo com a Seção 4(d) da Licença Apache 2.0, qualquer redistribuição ou trabalho derivado deve reter integralmente os avisos de atribuição contidos no arquivo [`NOTICE`](../../NOTICE).

</details>
