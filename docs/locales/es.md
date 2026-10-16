<div align="center">

<p align="center">
  <a href="../../README.md">🇺🇸 English</a> · <a href="./ko.md">🇰🇷 한국어</a> · <a href="./zh-CN.md">🇨🇳 中文</a> · <strong>🇪🇸 Español</strong> · <a href="./hi.md">🇮🇳 हिन्दी</a><br />
  <a href="./ar.md">🇸🇦 العربية</a> · <a href="./pt-BR.md">🇧🇷 Português</a> · <a href="./ru.md">🇷🇺 Русский</a> · <a href="./fr.md">🇫🇷 Français</a> · <a href="./id.md">🇮🇩 Bahasa Indonesia</a>
</p>

# shadow-vault (`svault`)

> Esteganografía de confianza cero y bóveda cifrada vinculada al hardware en doble capa — oculte archivos confidenciales dentro de portadores comunes de PNG/audio, séllelos con Argon2id + ChaCha20-Poly1305 + Windows DPAPI, o incruste bóvedas señuelo con denegabilidad plausible mediante doble contraseña.

[![Build](https://github.com/GHSFS/shadow-vault/actions/workflows/build.yml/badge.svg)](https://github.com/GHSFS/shadow-vault/actions/workflows/build.yml)
[![Tests](https://github.com/GHSFS/shadow-vault/actions/workflows/test.yml/badge.svg)](https://github.com/GHSFS/shadow-vault/actions/workflows/test.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](../../LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20x64-0078D6)](#-inicio-rápido-y-flujos-de-trabajo-cli)

</div>

---

## 🛡️ Descripción general y capacidades principales

<details open>
<summary><b>🛡️ Descripción general y capacidades principales</b></summary>
<br>

`shadow-vault` (`svault.exe`) es una caja de herramientas criptográfica y de esteganografía de binario único escrita en Rust sin dependencias externas, diseñada para operadores que requieren una protección de nivel militar para archivos de alto valor (frases semilla, claves privadas, credenciales, notas de investigación confidenciales):

1. **Cifrado autenticado de doble capa (`SVLT` v1/v2)** — combina derivación de claves con endurecimiento de memoria **Argon2id** + **ChaCha20-Poly1305** AEAD con vinculación opcional de hardware/sesión de usuario **Windows DPAPI (`CryptProtectData`)**. Incluso si un atacante roba físicamente el archivo `.svault` y la contraseña, una bóveda vinculada a DPAPI no puede descifrarse fuera de su cuenta de usuario de Windows.
2. **Denegabilidad plausible y bóvedas señuelo (`src/decoy.rs`)** — incrusta tanto un secreto principal oculto (desbloqueado con la contraseña maestra) como una carga señuelo inofensiva (desbloqueada con la contraseña señuelo) dentro de un único contenedor. Bajo coacción, revelar la contraseña señuelo solo desbloquea la carga señuelo, mientras que la ranura principal oculta permanece indistinguible estadísticamente del ruido aleatorio uniforme (relleno CSPRNG y texto cifrado ChaCha20-Poly1305).
3. **Esteganografía en medios sin pérdidas** — oculta contenedores cifrados dentro de archivos multimedia ordinarios:
   - **Imágenes PNG (`embed` / `extract`)**: inyecta un fragmento auxiliar privado `svLt` antes de `IEND` con sumas de comprobación CRC-32 IEEE 802.3 válidas (admite incrustación directa de bóvedas señuelo).
   - **Archivos de audio WAV (`embed-wav` / `extract-wav`)**: admite modos de subfragmento RIFF/WAVE (`--mode chunk`) y reemplazo de bit menos significativo (LSB) en muestras PCM de 16 bits (`--lsb`) con validación CRC-32.
   - **Imágenes BMP (`src/bmp.rs`)**: modula LSB a través de canales de píxeles RGB no comprimidos de 24 bits preservando estrictamente el relleno de fila de 4 bytes e integrando un sobre de 12 bytes resistente a manipulaciones (`svLt`, longitud, carga útil, CRC-32).
   - **Archivos de audio MP3 (`src/mp3/`)**: oculta cargas cifradas dentro de marcos de etiquetas privadas ID3v2.3/ID3v2.4 (`PRIV`) o relleno intertrama MPEG Audio Layer III con validación de sincronización de tramas, preservación de metadatos (TIT2, TPE1), comprobación CRC-32 y estimación de capacidad.
4. **Estimación universal de capacidad de portador (`capacity`)** — evalúa con precisión el tamaño total, la capacidad utilizable en bytes y la sobrecarga de esteganografía en portadores `.bmp`, `.wav`, `.png` y `.mp3` (`svault capacity <carrier> [--json]`).
5. **Esquema de secreto compartido de Shamir (`M-of-N`, `src/shamir.rs`)** — operaciones de cuerpo finito $\text{GF}(256)$ en tiempo constante y sin ramificaciones condicionales. Divide claves de recuperación maestras, contraseñas o contenedores en $N$ fragmentos requiriendo $M$ cualesquiera para reconstruir (`svault split` / `svault combine`). Admite texto blindado ASCII, cadenas compactas de una sola línea, serialización JSON y verificación SHA-256/CRC-32.
6. **Auditor de fortaleza de contraseña y entropía de portador (`src/audit.rs`)** — evalúa la resiliencia de contraseñas mediante bits de entropía de Shannon por byte, diversidad del conjunto de caracteres y detección de patrones vulnerables (caracteres repetidos, secuencias ascendentes/descendentes, caminatas en teclado, coincidencia con diccionarios leetspeak). Audita anomalías y manipulaciones en fragmentos PNG, flujos WAV RIFF/LSB, LSB de píxeles BMP de 24 bits y contenedores `.svault` (`svault audit <target>` / `svault audit -p <passphrase>`).
7. **Bóveda 2FA TOTP RFC 6238 (`src/totp.rs`)** — almacén local de autenticación de dos factores cifrado sin dependencias externas, sellado dentro de contenedores `.svault`. Incluye códec Base32 (RFC 4648), RFC 3174 SHA-1, RFC 2104 HMAC (SHA-1/256/512), analizador/serializador de URI `otpauth://totp/...`, verificación en tiempo constante contra ataques de canal lateral y barra de progreso con cuenta regresiva visual en terminal (`svault totp add`, `svault totp code`, `svault totp list`, `svault totp verify`).
8. **Protector de portapapeles con expiración automática (`src/clipboard_guard.rs`)** — copia credenciales de forma segura al portapapeles de Windows y las borra automáticamente tras un TTL configurable (ej. `--clip-ttl 15`). Inyecta formatos de privacidad de Windows 10/11 (`CanIncludeInClipboardHistory`, `ExcludeClipboardContentFromMonitorProcessing`) para inhibir el historial de portapapeles (Win + V) y la sincronización en la nube, realizando una comparación de huellas SHA-256 en tiempo constante (`constant_time_eq_32`) para evitar sobrescribir datos nuevos del usuario.
9. **Armadura de corrección de errores Cauchy Reed-Solomon (`src/armor.rs`)** — añade bandas de paridad y exportación/importación/reparación blindada ASCII `.svault.asc` para sobrevivir a la degradación de bits o corrupción en transmisiones de texto. Emplea una matriz generadora de Cauchy $[I_K; A]$ sobre $\text{GF}(256)$ garantizando propiedades MDS: CUALESQUIERA $K$ fragmentos intactos de $K + M$ bandas reconstruyen todos los datos originales. Admite autodetección de daños, autoreparación (`svault repair`), e integración en `inspect` y `audit`.
10. **Empaquetado de directorios y manifiesto multiactivo (`src/archive.rs`)** — empaqueta árboles de directorios completos con normalización de rutas relativas, prevención multicapa contra Zip Slip / escape de ruta, defensa contra bombas de descompresión, manifiestos criptográficos SHA-256 por archivo y preservación de permisos en un único contenedor sellado `SVLT` (`svault pack-dir` / `svault unpack-dir`). Admite `--list`, `--verify-only`, `--overwrite`, `--json`, `--dpapi` y extracción transparente desde portadores esteganográficos y armaduras ASCII.
11. **Derivación de clave de dos factores Keyfile + Contraseña (`src/keyfile.rs`)** — combina un archivo clave físico externo o USB (`--keyfile <path>`) con contraseñas de usuario mediante pre-hashing en flujo HMAC-SHA256 de 64 KiB antes de Argon2id. Admite 2FA (contraseña + archivo clave) y modo exclusivo de archivo clave, generación CSPRNG integrada (`svault keyfile generate`), huella digital SHA-256 e integración universal en todos los portadores y archivos de directorio.
12. **Cifrado en flujo fragmentado para archivos de varios GB (`src/stream.rs`)** — streaming autenticado en bloques de 4 MiB con derivación de Nonce independiente (contenedor `SVST` v1) para un uso de memoria constante $O(1)$ en archivos gigantes, protección de clave de flujo por Windows DPAPI, políticas temporales y CLI transparente.
13. **Informe comparativo visual y estadístico de portador estego (`src/diff.rs`)** — evalúa distorsión visual (MSE, PSNR, MAE, tasa de alternancia LSB pura), distorsión acústica de audio (SNR, PSNR), alineación de tablas de fragmentos y divergencia de entropía de Shannon $\Delta H$ (`svault compare <original> <stego>`).
14. **Interruptor de hombre muerto y guardia de autodestrucción por intentos (`src/guard.rs`)** — vincula contenedores y portadores a un registro inviolable (`.guard`). Si se alcanzan $K$ intentos fallidos consecutivos o vence el plazo de inactividad sin registro (`svault guard checkin`), ejecuta una destrucción criptográfica de 3 pasadas (0x00, 0xFF, CSPRNG) y desenlaza el archivo de forma permanente.
15. **Generador determinista y CSPRNG de contraseñas (`src/passgen/`)** — generación Diceware BIP-39 de 2.048 palabras, generación de contraseñas con eliminación de ambigüedad visual (`--exclude-ambiguous`), tokens de bytes aleatorios CSPRNG en Hex/Base64/Base32, derivación determinista por semilla maestra (`--seed`, `--context`), clasificación de entropía en 5 niveles e integración con protector de portapapeles (`svault keygen`).
16. **Salida JSON estructurada unificada (`--json`)** — todas las órdenes admiten respuestas en JSON estándar legible por máquina (`status`, `command`, métricas, tamaños en bytes, huellas), facilitando canalizaciones de scripts y automatización CI/CD.
17. **Rotación y reemplazo de claves de contenedor (`rotate`, `src/rotate.rs`)** — recifra contenedores `.svault` o portadores esteganográficos de forma atómica con nueva sal CSPRNG, Nonce y contraseñas/Keyfiles, admitiendo conmutación de DPAPI (`--dpapi`/`--no-dpapi`) o eliminación de políticas temporales (`--clear-policy`).
18. **Manifiesto de integridad desacoplado y canario (`canary`, `src/canary.rs`)** — genera y verifica listas canario SHA-256 firmadas con HMAC-SHA256 para supervisar árboles de directorios de bóvedas y portadores (`svault canary init` / `svault canary verify`).
19. **Motor de esteganografía MP3 ID3v2 y tramas de audio (`src/mp3/`)** — oculta cargas en archivos MPEG Audio Layer III mediante marcos de etiquetas privadas ID3v2 PRIV o relleno intertrama MPEG, ofreciendo detección transparente y denegabilidad plausible (`svault embed-mp3` / `svault extract-mp3`).
20. **Vinculación de credenciales de clave de hardware FIDO2 / Windows Hello (`src/hardware_token/`)** — vincula claves de cifrado a llaves físicas FIDO2 USB (YubiKey, SoloKey, etc.) o credenciales biométricas de Windows Hello (con respaldo TPM). Mezcla el secreto CTAP2 PRF (HMAC-Secret) con Argon2id mediante HMAC-SHA256 con separación de dominios y autentica encabezados `SVHW` en AAD (`svault fido2`).
21. **Encapsulación de clave híbrida poscuántica (`src/pq_kem/`)** — sellado asimétrico cuánticamente resistente de doble capa que combina **X25519** ECDH clásico con NIST **FIPS 203 ML-KEM-768**. Deriva claves simétricas ChaCha20-Poly1305 mediante HKDF-SHA256, generando contenedores binarios `SVPQ` v1 y armaduras ASCII (`svault kem keygen`, `svault kem seal`, `svault kem open`, `svault kem inspect`).
22. **Puesta a cero proactiva de memoria (`zeroize`)** — programas de claves intermedias sensibles, búferes de texto plano, coeficientes polinomiales de Shamir, secretos TOTP y texto plano de DPAPI se sobrescriben con ceros en memoria al salir de ámbito mediante `zeroize`.

</details>

---

## 🏛️ Arquitectura de almacenamiento y esteganografía

<details open>
<summary><b>🏛️ Arquitectura de almacenamiento y esteganografía</b></summary>
<br>

```text
  [ Secreto principal ] ──▶ [ ChaCha20-Poly1305 + Relleno CSPRNG ] ──┐ (Ranura oculta)
                                                                     │
  [ Carga señuelo ]     ──▶ [ Cifrado ChaCha20-Poly1305 ]          ──┴─▶ Contenedor SVLT v2 (.svault)
                                                                            ├── Almacenamiento directo en disco
                                                                            └── Portador estego
                                                                                  ├── Imagen PNG (.png)
                                                                                  ├── Audio WAV (.wav)
                                                                                  ├── Imagen BMP (.bmp)
                                                                                  └── Audio MP3 (.mp3)
```

</details>

---

## ⚡ Características principales y garantías de seguridad

<details open>
<summary><b>⚡ Características principales y garantías de seguridad</b></summary>
<br>

- **Argon2id + ChaCha20-Poly1305 AEAD** — sal aleatoria de 128 bits, Nonce aleatorio de 96 bits, derivación de clave de 256 bits separada por dominio y etiqueta de autenticación Poly1305 de 128 bits. Cualquier alteración provoca el rechazo inmediato del descifrado.
- **Protector de portapapeles con expiración automática (`clip`)**:
  - **Integración Win32 nativa**: llamadas directas a las API del portapapeles de Windows (`OpenClipboard`, `EmptyClipboard`, `SetClipboardData`, `CloseClipboard`) con 10 reintentos exponenciales.
  - **Inhibición de historial y nube**: escribe formatos de privacidad de Windows 10/11 (`CanIncludeInClipboardHistory`, `ExcludeClipboardContentFromMonitorProcessing`, `Clipboard Viewer Ignore`) para evitar su almacenamiento en el historial de Win+V o la nube de Microsoft.
  - **Verificación en tiempo constante**: comparación SHA-256 sin ramificaciones condicionales (`constant_time_eq_32`) que garantiza que el portapapeles solo se borre si aún contiene el secreto protegido, preservando nuevos textos copiados por el usuario.
  - **Cuenta regresiva visual y vaciado instantáneo**: barra de progreso dinámica en terminal (`[████████░░] 12s remaining`), atajo no bloqueante con tecla Enter y modo silencioso en segundo plano (`--silent`).
  - **Integración directa en comandos**: opciones `--clip` y `--clip-ttl <seg>` disponibles en `decrypt`, `decrypt-decoy`, `extract`, `extract-wav`, `totp code`, etc.
- **Bóveda 2FA TOTP RFC 6238 (`totp`)** — autenticador de dos factores multicuenta cifrado:
  - **Cero dependencias externas**: códec Base32 (RFC 4648), RFC 3174 SHA-1 y RFC 2104 HMAC (SHA-1/256/512) 100% verificados contra vectores de prueba oficiales.
  - **Vinculación de hardware y protección AEAD**: secretos de cuentas almacenados dentro de contenedores `.svault` cifrados mediante Argon2id + ChaCha20-Poly1305 y Windows DPAPI.
  - **Interoperabilidad con Key URI**: análisis y serialización canónica completa de URI `otpauth://totp/[Emisor:]Cuenta?...`.
  - **Defensa contra ataques de sincronización**: verificación en tiempo constante (`constant_time_eq`) y ventana de desfase temporal configurable ($\pm S$).
  - **Experiencia de usuario en terminal**: visualización de código en color, barra de progreso con segundos restantes (`[████████░░] 19s`) y modo `--json`.
- **Auditor de fortaleza de contraseñas y entropía (`audit`)**:
  - **Cálculo de entropía de Shannon y de conjunto**: bits exactos por byte ($0.0 \le H \le 8.0$), bits totales y entropía de espacio de caracteres ($L \log_2 R$).
  - **Detección de patrones y vulnerabilidades**: secuencias (`1234`, `abcd`), repeticiones (`aaaa`), patrones de teclado (`qwerty`, `asdfgh`) y coincidencias de diccionario leetspeak (`p@ssw0rd`).
  - **Estimación de tiempo de descifrado multivectorial**: ataques en línea con límite de tasa (100/s), Argon2id fuera de línea ($10^3$/s) y clúster GPU fuera de línea ($10^{10}$/s).
  - **Esteganálisis de portadores**: inspección de fragmentos PNG, datos residuales tras `IEND`, subfragmentos WAV RIFF `svLt`, flujos PCM LSB de 16 bits y pruebas de uniformidad Chi-cuadrado ($\chi^2$).
- **Esquema de secreto compartido de Shamir ($M$-de-$N$)**:
  - **Aritmética de cuerpo en tiempo constante**: multiplicación de campesino sin ramificaciones e inversión de Fermat ($a^{-1} = a^{254}$) en $\text{GF}(256)$ sin búsquedas en tablas.
  - **Integridad de doble capa**: resumen SHA-256 incrustado para evitar falsificaciones con fragmentos manipulados y CRC-32 por fragmento contra corrupciones de transmisión.
  - **Formatos flexibles**: bloques blindados ASCII (`-----BEGIN SHADOW VAULT SHARE-----`), cadenas compactas (`SVLT-S1-...`) y JSON estructurado.
- **Contenedores de denegabilidad plausible con doble contraseña**:
  - **Descifrado transparente**: `svault decrypt -p <passphrase>` detecta y desbloquea automáticamente la ranura correspondiente a la contraseña suministrada.
  - **Ranura oculta indistinguible**: sin cabeceras mágicas en texto plano ni campos de longitud para el volumen oculto; los bytes finales presentan máxima entropía (~8.0 bits/byte).
  - **Relleno de ofuscación de tamaño (`--padding <bytes>`)**: rellenos aleatorios CSPRNG o alineación predeterminada a 256 bytes para evitar análisis de longitud de archivo.
- **Vinculación de sesión/hardware (`--dpapi`)** — envuelve el texto cifrado con Windows DPAPI de modo que la descifrado se restringe al perfil de usuario de Windows originario.
- **Puesta a cero proactiva de memoria (`zeroize`)** — búferes de claves y texto plano se borran de la memoria con barreras de compilador al descartarse.
- **Esteganografía PNG sin pérdidas (`embed` / `extract`)** — inyecta un fragmento auxiliar `svLt` antes de `IEND` con validación CRC-32 completa; admite incrustación de bóvedas señuelo.
- **Esteganografía en audio WAV (`embed-wav` / `extract-wav`)**:
  - **Modo subfragmento RIFF (`--mode chunk`)**: adjunta fragmento de metadatos `svLt` con CRC-32.
  - **Modo LSB PCM de 16 bits (`--lsb`)**: modifica el bit menos significativo de muestras de 16 bits sin alterar la duración ni la percepción acústica.
  - **Autodetección**: `extract-wav` reconoce y desempaqueta automáticamente portadores de fragmento y de LSB.
- **Esteganografía LSB en píxeles BMP de 24 bits (`embed-bmp` / `extract-bmp`)**:
  - **Preservación del relleno de fila**: navega la alineación de fila de 4 bytes e incrusta únicamente en canales R, G, B sin corromper la imagen.
  - **Sobre de 12 bytes inviolable**: encuadra la carga en `[svLt: 4B][len: 4B LE][payload: NB][crc32: 4B LE]` con comprobación CRC-32 en tiempo constante.
  - **Auditoría e integración**: compatibilidad total con `audit`, bóvedas señuelo y protector de portapapeles.
- **Armadura de corrección de errores Cauchy Reed-Solomon (`armor` / `dearmor` / `repair`)**:
  - **Código Cauchy MDS sobre $\text{GF}(256)$**: utiliza la matriz generadora $[I_K; A]$ con $A_{i, j} = \frac{1}{(K + i) \oplus j}$. $K$ fragmentos intactos cualesquiera de $K + M$ bandas reconstruyen todos los datos mediante eliminación gaussiana.
  - **Comprobación CRC-32 por banda y SHA-256 global**: aísla fallos con precisión de banda y autentica el contenedor reconstruido con SHA-256.
  - **Reparación autorreparable (`repair`)**: reconstruye bandas dañadas y genera un archivo `.svault.asc` limpio o lo exporta directamente a binario (`--binary`).
  - **Recuperación transparente en `dearmor`**: activa automáticamente la reconstrucción de borrado si se detectan bandas dañadas en tránsito.
- **Empaquetado de directorios y manifiesto multiactivo (`pack-dir` / `unpack-dir`)**:
  - **Formato binario `SVAR`**: cabecera de 18 bytes (`SVAR` v1), metadatos por entrada, resúmenes SHA-256 individuales y suma CRC-32 de 8 bytes con magia `SVEN`.
  - **Prevención de Zip Slip y escape de ruta**: normaliza a `/`, rechaza `..`, rutas absolutas/UNC, flujos ADS de dos puntos y nombres de dispositivos reservados de Windows.
  - **Defensa contra bombas de descompresión**: límites máximos de 8 GiB totales, 4 GiB por archivo, 100.000 entradas y 64 niveles de profundidad.
- **Estimación universal de capacidad de portador (`capacity`)** — calcula capacidad total, capacidad utilizable y sobrecarga esteganográfica en portadores `.bmp`, `.wav`, `.png` y `.mp3`.
- **Inspección de cabecera sin conocimiento (`inspect`)** — visualiza versión de contenedor, indicador DPAPI, presencia de señuelo y sal sin descifrar ni revelar el tamaño de la ranura oculta.
- **Políticas temporales de bloqueo y expiración (`policy`)**:
  - **Cabecera de política autenticada (`SVPO`)**: cabecera canónica de 28 bytes con marcas temporales, descripción y CRC-32.
  - **Vinculación AAD en AEAD**: todo el bloque de política se inyecta como datos asociados autenticados (`aad`) en ChaCha20-Poly1305.
- **Derivación Keyfile + Contraseña (`keyfile`)**:
  - **HMAC-SHA256 en flujo de 64 KiB**: lee archivos clave de cualquier tamaño en memoria constante de 64 KiB con borrado seguro.
  - **Modos 2FA y solo archivo clave**: alimenta una semilla de 256 bits a Argon2id.
- **Cifrado en flujo fragmentado (`stream`)** — streaming en memoria constante $O(1)$ para archivos de varios gigabytes.
- **Informe diferencial visual y estadístico (`compare`)** — compara calidad MSE/PSNR/MAE en imágenes, SNR/PSNR en audio, tablas de fragmentos y desplazamiento de entropía $\Delta H$.
- **Guardia de autodestrucción por intentos y hombre muerto (`guard`)** — registra intentos en un libro de contabilidad inviolable; destruye el archivo permanentemente con 3 pasadas al alcanzar el umbral.
- **Generador determinista y CSPRNG de contraseñas (`keygen`)** — frases de recuperación Diceware BIP-39, contraseñas sin ambigüedad y derivación determinista por semilla.
- **Shell interactivo en memoria (`repl`)** — almacenamiento clave-valor en memoria con descifrado único, protegido por portapapeles con expiración automática.
- **Destructor seguro de archivos en 3 pasadas (`shred`)** — sobrescribe archivos con `0x00`, `0xFF` y bytes aleatorios CSPRNG antes de desenlazar.
- **Binario estático único** — compilado con `+crt-static`, LTO y símbolos eliminados, sin dependencias externas de ejecución.

</details>

---

## 🚀 Inicio rápido y flujos de trabajo CLI

<details open>
<summary><b>🚀 Inicio rápido y flujos de trabajo CLI (Haga clic en la categoría para plegar / desplegar)</b></summary>
<br>

<details open>
<summary><b>🔐 1. Cifrado de doble capa y señuelos con denegabilidad plausible (#1 - #6)</b></summary>
<br>

```bash
# 1. Cifrar un archivo con contraseña y vinculación de hardware Windows DPAPI
svault encrypt -i wallet-seed.txt -o wallet.svault -p "your-strong-passphrase" --dpapi

# 2. Cifrar una bóveda con denegabilidad plausible que contiene el secreto real y una carga señuelo
svault encrypt -i classified.txt --decoy shopping-list.txt -o deniable.svault \
  -p "primary-secret-pass" --decoy-passphrase "decoy-harmless-pass" --padding 512

# 3. Descifrar contenedor plausible (proporcionar la contraseña señuelo solo libera los datos inofensivos)
svault decrypt -i deniable.svault -o revealed.txt -p "decoy-harmless-pass"
# Proporcionar la contraseña principal recupera el secreto real
svault decrypt -i deniable.svault -o restored.txt -p "primary-secret-pass"

# 4. Inspeccionar metadatos de la bóveda sin descifrar (.svault, .png, .wav o .bmp)
svault inspect deniable.svault

# 5. Ocultar una bóveda señuelo de doble contraseña directamente dentro de una imagen PNG
svault embed -c wallpaper.png -s classified.txt --decoy shopping-list.txt -o wallpaper-stego.png \
  -p "primary-secret-pass" --decoy-passphrase "decoy-harmless-pass"

# 6. Extraer el secreto desde la imagen PNG (con la contraseña principal o señuelo)
svault extract -c wallpaper-stego.png -o restored-seed.txt -p "primary-secret-pass"
svault extract -c wallpaper-stego.png -o decoy-seed.txt --decoy-passphrase "decoy-harmless-pass"
```

</details>

<details open>
<summary><b>🖼️ 2. Esteganografía sin pérdidas en medios: PNG, WAV, BMP, MP3 y capacidad (#7 - #13)</b></summary>
<br>

```bash
# 7. Ocultar un secreto dentro de un archivo de audio WAV (subfragmento RIFF o PCM LSB de 16 bits)
svault embed-wav -c track.wav -s classified.txt -o track-lsb.wav -p "primary-secret-pass" --lsb

# 8. Extraer y descifrar el secreto de un archivo WAV (autodetección de subfragmento o LSB)
svault extract-wav -c track-lsb.wav -o restored-audio.txt -p "primary-secret-pass"

# 9. Estimar la capacidad de portador disponible para esteganografía (.bmp, .wav, .png o .mp3)
svault capacity landscape.bmp
svault capacity track.wav --json
svault capacity song.mp3

# 10. Ocultar un secreto en una imagen BMP de 24 bits mediante esteganografía LSB en píxeles
svault embed-bmp -c landscape.bmp -s classified.txt -o landscape-stego.bmp -p "primary-secret-pass"

# 11. Extraer el secreto de una imagen BMP directamente al portapapeles con autoexpiración (15 seg)
svault extract-bmp -c landscape-stego.bmp -p "primary-secret-pass" --clip --clip-ttl 15

# 12. Ocultar un secreto en un archivo de audio MP3 (etiqueta ID3v2 PRIV o relleno intertrama)
svault embed-mp3 -c song.mp3 -s classified.txt -o song-stego.mp3 -p "primary-secret-pass" --mode id3v2
svault embed-mp3 -c song.mp3 -s classified.txt -o song-frame.mp3 -p "primary-secret-pass" --mode frame

# 13. Extraer el secreto de un archivo de audio MP3 (autodetección de modo)
svault extract-mp3 -c song-stego.mp3 -o restored-mp3.txt -p "primary-secret-pass"
```

</details>

<details open>
<summary><b>🧩 3. Destrucción segura, secreto compartido de Shamir y auditoría de entropía (#12 - #16)</b></summary>
<br>

```bash
# 12. Destruir de forma segura el archivo de texto plano original (3 pasadas)
svault shred classified.txt --passes 3

# 13. Dividir una clave de recuperación maestra en fragmentos Shamir 3-de-5
svault split -s "your-master-seed-or-secret" -m 3 -n 5 -o shares/share

# 14. Combinar 3 fragmentos cualesquiera para reconstruir el secreto original
svault combine shares/share_1.share shares/share_3.share shares/share_5.share -o restored.txt

# 15. Auditar la fortaleza de la contraseña, entropía de Shannon y tiempo de fuerza bruta
svault audit -p "Correct-Horse-Battery-Staple-2026!"

# 16. Auditar una imagen portadora estego o contenedor en busca de anomalías y cargas ocultas
svault audit wallpaper-stego.png --json
```

</details>

<details open>
<summary><b>⏱️ 4. Bóveda TOTP 2FA RFC 6238 y protector de portapapeles autoexpirable (#17 - #23)</b></summary>
<br>

```bash
# 17. Agregar credencial TOTP 2FA mediante secreto Base32 o URI otpauth://
svault totp add github --secret "JBSWY3DPEHPK3PXP" --issuer "GitHub" --vault totp.svault -p "vault-pass"
svault totp add --uri "otpauth://totp/Google:alice?secret=JBSWY3DPEHPK3PXP&issuer=Google" --vault totp.svault -p "vault-pass"

# 18. Generar código OTP 2FA en tiempo real con barra de cuenta regresiva visual (o --json)
svault totp code github --vault totp.svault -p "vault-pass"
svault totp code github --vault totp.svault -p "vault-pass" --json

# 19. Verificar un código OTP con ventana de tolerancia de desfase (+/- 1 paso)
svault totp verify github 123456 --skew 1 --vault totp.svault -p "vault-pass"

# 20. Listar y exportar cuentas 2FA
svault totp list --vault totp.svault -p "vault-pass"
svault totp export github --vault totp.svault -p "vault-pass"

# 21. Copiar secreto al portapapeles con autodestrucción en 15 segundos (o modo silencioso)
svault clip copy "my-super-secret-password" --ttl 15
svault clip copy "my-super-secret-password" --ttl 15 --silent

# 22. Comprobar el estado del portapapeles y metadatos de exclusión, o borrar manualmente
svault clip status
svault clip clear

# 23. Descifrar directamente al portapapeles protegido sin imprimir en terminal ni guardar en disco
svault decrypt -i secret.svault -p "vault-pass" --clip --clip-ttl 30
svault totp code github --vault totp.svault -p "vault-pass" --clip --clip-ttl 15
```

</details>

<details open>
<summary><b>🛡️ 5. Armadura Cauchy Reed-Solomon y empaquetado de directorios (#24 - #30)</b></summary>
<br>

```bash
# 24. Proteger contenedor .svault con armadura ASCII y bandas de paridad Reed-Solomon (.svault.asc)
svault armor -i secret.svault -o secret.svault.asc -k 4 -m 2

# 25. Revertir un archivo blindado ASCII al contenedor binario .svault original
svault dearmor -i secret.svault.asc -o recovered.svault

# 26. Reparar un archivo .svault.asc dañado mediante paridad Cauchy Reed-Solomon
svault repair -i corrupted.svault.asc -o repaired.svault.asc --json
svault repair -i corrupted.svault.asc -o direct_recovered.svault --binary

# 27. Inspeccionar y auditar las bandas de un contenedor blindado ASCII y su integridad
svault inspect secret.svault.asc
svault audit secret.svault.asc --json

# 28. Empaquetar un árbol de directorios completo en un contenedor cifrado .svault
svault pack-dir -i ./my_project -o project.svault -p "pack-passphrase" --list

# 29. Empaquetar directamente en un portador estego (PNG, WAV, BMP, MP3) o armadura ASCII
svault pack-dir -i ./my_project -o project.png -p "pack-passphrase" --carrier cover.png
svault pack-dir -i ./my_project -o project.svault.asc -p "pack-passphrase" --armor

# 30. Desempaquetar archivo, inspeccionar manifiesto o verificar resúmenes criptográficos
svault unpack-dir -i project.svault -p "pack-passphrase" --list
svault unpack-dir -i project.svault -p "pack-passphrase" --verify-only
svault unpack-dir -i project.svault -o ./restored_project -p "pack-passphrase" --overwrite
```

</details>

<details open>
<summary><b>⏳ 6. Políticas de bloqueo temporal, USB Keyfiles y streaming fragmentado (#31 - #42)</b></summary>
<br>

```bash
# 31. Cifrar con política de bloqueo temporal (no se puede abrir antes de la fecha futura)
svault encrypt -i escrow.txt -o escrow.svault -p "vault-pass" --not-before "2026-12-31T00:00:00Z" --policy-desc "Year-End Escrow"

# 32. Cifrar con política de autoexpiración (expira en 2 horas o en una fecha ISO específica)
svault encrypt -i token.txt -o token.svault -p "vault-pass" --expires-in 2h --policy-desc "Session Token"
svault encrypt -i doc.txt -o doc.svault -p "vault-pass" --expires-at "2026-10-15"

# 33. Inspeccionar metadatos de política sin descifrar (texto legible y JSON)
svault inspect escrow.svault
svault inspect escrow.svault --json

# 34. Probar el descifrado contra una marca de tiempo de referencia explícita
svault decrypt -i escrow.svault -o restored.txt -p "vault-pass" --at-time "2027-01-01"

# 35. Generar un archivo clave criptográfico USB (CSPRNG, por defecto 64 bytes)
svault keyfile generate -o usb_token.key --bytes 64

# 36. Inspeccionar huella digital y entropía de Shannon del archivo clave (texto y JSON)
svault keyfile inspect usb_token.key
svault keyfile inspect usb_token.key --json
svault keyfile fingerprint usb_token.key

# 37. Cifrar y descifrar con doble factor 2FA (Contraseña + Archivo clave)
svault encrypt -i secret.txt -o sealed.svault -p "master-pass" -k usb_token.key
svault decrypt -i sealed.svault -o restored.txt -p "master-pass" -k usb_token.key

# 38. Cifrado exclusivo con archivo clave sin contraseña
svault encrypt -i token.txt -o hardware.svault -k usb_token.key
svault decrypt -i hardware.svault -o restored.txt -k usb_token.key

# 39. Empaquetar directorio en bóveda cifrada con 2FA de archivo clave
svault pack-dir -i ./confidential -o archive.svault -p "pack-pass" -k usb_token.key
svault unpack-dir -i archive.svault -o ./unpacked -p "pack-pass" -k usb_token.key

# 40. Cifrar archivos de varios gigabytes con streaming fragmentado (bloques de 4 MiB o a medida)
svault stream encrypt -i large_dataset.iso -o large_dataset.svault -p "stream-pass"
svault encrypt -i database.backup -o db.svault -p "stream-pass" --stream --chunk-size 8M

# 41. Descifrar contenedor en flujo (reconoce formato SVST o mediante subcomando stream)
svault decrypt -i large_dataset.svault -o restored.iso -p "stream-pass"
svault stream decrypt -i db.svault -o restored_db.backup -p "stream-pass"

# 42. Inspeccionar metadatos de contenedor en streaming sin descifrar
svault stream inspect large_dataset.svault
svault inspect large_dataset.svault --json
```

</details>

<details open>
<summary><b>🚨 7. Informes de diferencias estego, guardia de autodestrucción y contraseñas (#43 - #53)</b></summary>
<br>

```bash
# 43. Comparar portador original contra portador estego (PNG, BMP, WAV o binario)
svault compare cover.bmp stego.bmp
svault compare cover.png stego.png --json
svault diff original.wav stego.wav --detailed

# 44. Armar una bóveda con guardia de autodestrucción a 3 intentos e interruptor de hombre muerto
svault encrypt -i secret.txt -o guarded.svault -p "vault-pass" --max-attempts 3 --dead-man 7d --guard-companion

# 45. Armar directamente un portador o contenedor existente
svault guard arm -t stego.png --max-attempts 3 --companion
svault guard arm -t vault.svault --max-attempts 5 --dead-man 24h

# 46. Inspeccionar el estado de la guardia y los intentos restantes (texto y JSON)
svault guard status -t guarded.svault
svault guard status -t guarded.svault --json

# 47. Registrarse para actualizar el plazo de hombre muerto o reiniciar el contador de fallos
svault guard checkin -t guarded.svault --interval 30d
svault guard reset -t guarded.svault

# 48. Desarmar la guardia o activar la destrucción instantánea de emergencia en múltiples pasadas
svault guard disarm -t guarded.svault
svault guard trigger -t guarded.svault --force --passes 3

# 49. Generar frase de recuperación Diceware BIP-39 de 6 palabras
svault keygen --words 6

# 50. Generar Diceware personalizado con números y mayúsculas
svault keygen --words 4 --separator "." --capitalize --number

# 51. Generar contraseña de 24 caracteres con filtro de ambigüedad y análisis de entropía
svault keygen --length 24 --exclude-ambiguous --entropy

# 52. Derivación determinista de contraseña a partir de semilla maestra y contexto de servicio
svault keygen --words 6 --seed "master-recovery-seed" --context "github-token"

# 53. Generar token criptográfico aleatorio de 32 bytes y copiarlo al portapapeles
svault keygen --bytes 32 --base64 --clip --clip-ttl 30
svault keygen --bytes 20 --base32 --json
```

</details>

<details open>
<summary><b>💻 8. Rotación de claves, integridad con canario y shell interactivo REPL (#54 - #63)</b></summary>
<br>

```bash
# 54. Rotar claves del contenedor con nueva contraseña, sal y Nonce frescos
svault rotate -i vault.svault -o rotated.svault -p "old-secret" -n "new-secret"

# 55. Rotar contenedor o portador in-situ de forma atómica
svault rotate -i vault.svault --in-place -p "old-secret" -n "new-secret"
svault rotate -i stego.bmp --in-place -p "old-pass" -n "new-pass"

# 56. Rotar credenciales en portador estego (PNG, WAV, BMP o armadura ASCII)
svault rotate -i carrier.png -o rotated.png -p "old-pass" -n "new-pass"
svault rotate -i carrier.asc -o rotated.asc -p "old-pass" -n "new-pass"

# 57. Rotar cambiando la vinculación de hardware DPAPI o borrando políticas
svault rotate -i vault.svault -o dpapi_vault.svault -p "old-pass" -n "new-pass" --dpapi
svault rotate -i locked.svault -o unlocked.svault -p "old-pass" -n "new-pass" --clear-policy --json

# 58. Inicializar manifiesto canario de integridad desacoplado para el directorio objetivo
svault canary init -d ./vaults
svault canary init -d ./vaults -p "canary-auth-secret" --json

# 59. Verificar integridad canario contra alteraciones de archivos en disco
svault canary verify -d ./vaults
svault canary verify -d ./vaults -p "canary-auth-secret" --strict --json

# 60. Iniciar shell REPL interactivo de bóveda clave-valor en memoria
svault repl -v myvault.svault -p "session-pass"

# 61. Ejecutar comandos REPL por lotes de forma no interactiva con --exec
svault repl -v myvault.svault -p "session-pass" --exec "set api_key sk_live_xyz --tag prod; set db_pass secret; save"

# 62. Consultar secreto directamente protegido por portapapeles con autoexpiración
svault repl -v myvault.svault -p "session-pass" --exec "get api_key --clip --clip-ttl 15"

# 63. Abrir REPL en modo de solo lectura o exportar entradas a JSON
svault repl -v myvault.svault -p "session-pass" --readonly --exec "list" --json
svault repl -v myvault.svault -p "session-pass" --exec "export ./backup.json; exit"
```

</details>

<details open>
<summary><b>🔑 9. Vinculación de credenciales de clave física FIDO2 / Windows Hello (#64 - #70)</b></summary>
<br>

```bash
# 64. Inspeccionar soporte de hardware de plataforma (Windows Hello, API WebAuthn, USB HID)
svault fido2 status
svault fido2 status --json

# 65. Registrar llave USB FIDO2 o credencial de Windows Hello
svault fido2 enroll yubikey-5c --type usb --user alice --output ./yubikey.json
svault fido2 enroll hello-tpm --type hello --pin 849201 --json

# 66. Probar aserción del autenticador y verificar huella de derivación PRF
svault fido2 test ./yubikey.json
svault fido2 test ./yubikey.json --json

# 67. Cifrar contenedor vinculando credencial FIDO2 + contraseña maestra
svault encrypt -i secret.txt -o sealed.svault --fido2-cred ./yubikey.json -p "master-pass"

# 68. Descifrar contenedor utilizando la credencial de hardware registrada
svault decrypt -i sealed.svault -o restored.txt --fido2-cred ./yubikey.json -p "master-pass"

# 69. Autenticación multifactor 2FA: Archivo clave + token FIDO2 físico (sin contraseña)
svault encrypt -i secret.txt -o mfa.svault -k usb_token.key --fido2-cred ./yubikey.json
svault decrypt -i mfa.svault -o restored.txt -k usb_token.key --fido2-cred ./yubikey.json

# 70. Rotar contenedor existente para agregar o desvincular credenciales de hardware FIDO2
svault rotate -i sealed.svault --in-place -p "old-pass" -n "new-pass" --fido2 --fido2-cred ./yubikey.json
svault rotate -i sealed.svault --in-place -p "new-pass" -n "plain-pass" --no-fido2 --fido2-cred ./yubikey.json
```

</details>

<details open>
<summary><b>⚛️ 10. Encapsulación de clave híbrida poscuántica (X25519 + ML-KEM-768) (#71 - #74)</b></summary>
<br>

```bash
# 71. Generar par de claves híbridas poscuánticas (X25519 + ML-KEM-768)
svault kem keygen -p recipient.pub -s recipient.key
svault kem keygen -p recipient.pub -s recipient.key --json

# 72. Sellar un archivo confidencial para la clave pública del receptor (binario o armadura ASCII)
svault kem seal -i classified.txt -o sealed.svault.pq -k recipient.pub
svault kem seal -i classified.txt -o sealed.asc -k recipient.pub --armor --json

# 73. Inspeccionar metadatos de contenedor poscuántico (clave efímera, tamaño criptograma, CRC-32)
svault kem inspect -i sealed.svault.pq
svault kem inspect -i sealed.asc --json

# 74. Abrir y descifrar la bóveda poscuántica mediante la clave privada del receptor
svault kem open -i sealed.svault.pq -o restored.txt -k recipient.key
svault kem open -i sealed.asc -o restored.txt -k recipient.key --json
```

</details>

</details>

---

## 🔒 Seguridad de memoria e invariantes de protección

<details open>
<summary><b>🔒 Seguridad de memoria e invariantes de protección</b></summary>
<br>

- **100% Rust seguro y criptografía en tiempo constante**: Sin bloques `unsafe` en las rutas de datos criptográficos; aritmética en cuerpos de Galois sin ramificaciones para impedir ataques de canal lateral temporales.
- **Puesta a cero proactiva de memoria**: Los búferes de claves intermedias, el texto plano y las semillas PRF implementan puesta a cero protegida contra optimizaciones del compilador en Drop mediante `zeroize`.
- **Vinculación a perfil de hardware**: El encapsulamiento opcional con Windows DPAPI garantiza que el texto cifrado no pueda descifrarse fuera del equipo y la sesión de usuario que lo originó.
- **Defensas contra Zip Slip y bombas de descompresión**: Rutas relativas canónicas, verificaciones estrictas y límites rígidos de asignación de memoria evitan ataques de agotamiento de recursos.

</details>

---

## 📄 Licencia y atribución

<details open>
<summary><b>📄 Licencia y atribución</b></summary>
<br>

Copyright 2026 **GHSFS** ([https://github.com/GHSFS](https://github.com/GHSFS)).

Distribuido bajo la **Licencia Apache, Versión 2.0** ([`LICENSE`](../../LICENSE)).
De conformidad con la Sección 4(d) de la Licencia Apache 2.0, cualquier redistribución o trabajo derivado debe conservar íntegramente los avisos de atribución contenidos en [`NOTICE`](../../NOTICE).

</details>
