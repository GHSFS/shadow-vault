<div align="center">

<p align="center">
  <a href="../../README.md">🇺🇸 English</a> · <a href="./ko.md">🇰🇷 한국어</a> · <a href="./zh-CN.md">🇨🇳 中文</a> · <strong>🇪🇸 Español</strong> · <a href="./hi.md">🇮🇳 हिन्दी</a><br />
  <a href="./ar.md">🇸🇦 العربية</a> · <a href="./pt-BR.md">🇧🇷 Português</a> · <a href="./ru.md">🇷🇺 Русский</a> · <a href="./fr.md">🇫🇷 Français</a> · <a href="./id.md">🇮🇩 Bahasa Indonesia</a>
</p>

# shadow-vault (`svault`)

> Bóveda criptográfica con esteganografía de confianza cero y vinculación de hardware en doble capa: oculte archivos confidenciales dentro de portadores comunes de PNG/audio, séllelos con Argon2id + ChaCha20-Poly1305 + Windows DPAPI, o incorpore bóvedas señuelo con negación plausible de doble contraseña.

[![Build](https://github.com/GHSFS/shadow-vault/actions/workflows/build.yml/badge.svg)](https://github.com/GHSFS/shadow-vault/actions/workflows/build.yml)
[![Tests](https://github.com/GHSFS/shadow-vault/actions/workflows/test.yml/badge.svg)](https://github.com/GHSFS/shadow-vault/actions/workflows/test.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](../../LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20x64-0078D6)](#inicio-rápido)

</div>

---

### Descripción General

`shadow-vault` (`svault.exe`) es un conjunto de herramientas criptográficas y de esteganografía en un único binario sin dependencias externas escrito en Rust. Diseñado para operadores que requieren máxima protección para archivos de alto valor (frases semilla, claves privadas, credenciales y notas de investigación):

1. **Cifrado Autenticado de Doble Capa (`SVLT` v1/v2)** — combina derivación de claves con **Argon2id** (resistente a memoria) + **ChaCha20-Poly1305** AEAD con vinculación opcional de sesión/máquina vía **Windows DPAPI (`CryptProtectData`)**.
2. **Negación Plausible y Bóvedas Señuelo (`src/decoy.rs`)** — incrusta tanto un secreto principal oculto como una carga señuelo inofensiva en un solo contenedor. Bajo coacción, la contraseña señuelo solo revela la carga inofensiva, mientras la ranura oculta permanece indistinguible de ruido aleatorio uniforme.
3. **Esteganografía sin Pérdida en Medios Portadores**:
   - **Imágenes PNG**: inyecta un fragmento privado auxiliar `svLt` antes de `IEND` con validación CRC-32 IEEE 802.3.
   - **Archivos WAV**: compatible con subfragmentos RIFF/WAVE (`svLt`) y modulación LSB en muestras PCM de 16 bits.
   - **Imágenes BMP**: modulación LSB en canales RGB de 24 bits con preservación de alineación de 4 bytes y sobre de 12 bytes.
   - **Archivos MP3 (`src/mp3/`)**: ocultación dentro de marcos privados `PRIV` ID3v2 o relleno intermarco MPEG Audio Layer III.
4. **Estimación Universal de Capacidad de Portadores (`capacity`)** — cálculo de capacidad útil en `.bmp`, `.wav`, `.png`, `.mp3`.
5. **Esquema de Secreto Compartido de Shamir (`M-de-N`, `src/shamir.rs`)** — aritmética de tiempo constante en $\text{GF}(256)$ para dividir claves o contenedores en $N$ fragmentos con umbral de reconstrucción $M$.
6. **Auditor de Fortaleza de Contraseñas y Entropía (`src/audit.rs`)** — cálculo de entropía de Shannon, detección de patrones vulnerables y auditoría de portadores.
7. **Bóveda TOTP 2FA RFC 6238 (`src/totp.rs`)** — autenticador 2FA local autónomo con Base32 y HMAC (SHA-1/256/512) sin dependencias.
8. **Protector de Portapapeles con Expiración Automática (`src/clipboard_guard.rs`)** — supresión de historial de Windows 10/11 y borrado seguro con TTL y verificación constante SHA-256.
9. **Armadura de Corrección de Errores Cauchy Reed-Solomon (`src/armor.rs`)** — matriz Cauchy MDS en $\text{GF}(256)$ que permite reconstruir todos los datos a partir de $K$ fragmentos intactos de un total de $K+M$.
10. **Empaquetado de Directorios y Manifiesto Multifarchivo (`src/archive.rs`)** — prevención contra Zip Slip / Zip Bomb con resúmenes criptográficos SHA-256 por archivo.
11. **Derivación 2FA con Keyfile + Contraseña (`src/keyfile.rs`)** — pre-hashing HMAC-SHA256 en búferes de 64 KiB para tokens USB.
12. **Cifrado por Flujo en Bloques de 4 MiB (`src/stream.rs`)** — procesamiento en memoria constante $O(1)$ para archivos de varios gigabytes.
13. **Reporte de Diferencias Visuales y Estadísticas (`src/diff.rs`)** — evaluación de MSE, PSNR, SNR y desviación de entropía $\Delta H$.
14. **Interruptor de Hombre Muerto y Autodestrucción (`src/guard.rs`)** — trituración criptográfica en 3 pasadas (0x00, 0xFF, CSPRNG) ante $K$ intentos fallidos consecutivos.
15. **Generador Determinista y CSPRNG de Contraseñas (`src/passgen/`)** — frases de recuperación BIP-39 Diceware de 2,048 palabras.
16. **Salida Estructurada JSON Unificada (`--json`)** — telemetría legible por máquina en todos los subcomandos.
17. **Rotación de Claves de Contenedor (`rotate`)** — recifrado atómico in situ con nueva sal, nonce y contraseña.
18. **Canario y Manifiesto de Integridad (`canary`)** — generación y verificación de firmas de integridad en árboles de archivos.
19. **Vinculación con FIDO2 y Windows Hello (`src/hardware_token/`)** — integración con llaves USB (YubiKey) y biometría TPM vía CTAP2 PRF.
20. **Encapsulamiento Híbrido Poscántico (`src/pq_kem/`)** — sellado asimétrico resistente a computación cuántica combinando X25519 con NIST FIPS 203 ML-KEM-768.
21. **Limpieza Activa de Memoria (`zeroize`)** — sobrescritura inmediata de búferes de claves sensibles al salir del ámbito.

### Inicio Rápido

```bash
# 1. Cifrar un archivo con contraseña y vinculación DPAPI
svault encrypt -i wallet-seed.txt -o wallet.svault -p "your-strong-passphrase" --dpapi

# 2. Cifrar bóveda de negación plausible con secreto y señuelo
svault encrypt -i classified.txt --decoy shopping-list.txt -o deniable.svault \
  -p "primary-secret-pass" --decoy-passphrase "decoy-harmless-pass" --padding 512

# 3. Desbloquear con contraseña señuelo (solo revela lista de compras)
svault decrypt -i deniable.svault -o revealed.txt -p "decoy-harmless-pass"

# 4. Inspeccionar metadatos del contenedor sin descifrar
svault inspect deniable.svault

# 5. Ocultar bóveda dentro de una imagen PNG
svault embed -c wallpaper.png -s classified.txt --decoy shopping-list.txt -o wallpaper-stego.png \
  -p "primary-secret-pass" --decoy-passphrase "decoy-harmless-pass"

# 6. Extraer secreto real desde la imagen PNG
svault extract -c wallpaper-stego.png -o restored-seed.txt -p "primary-secret-pass"
```

### Licencia y Atribución

Copyright 2026 **GHSFS** ([https://github.com/GHSFS](https://github.com/GHSFS)).

Distribuido bajo la **Licencia Apache 2.0** ([LICENSE](../../LICENSE)). Las redistribuciones deben conservar los avisos de atribución contenidos en [NOTICE](../../NOTICE).
