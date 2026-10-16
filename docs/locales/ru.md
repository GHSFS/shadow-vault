<div align="center">

<p align="center">
  <a href="../../README.md">🇺🇸 English</a> · <a href="./ko.md">🇰🇷 한국어</a> · <a href="./zh-CN.md">🇨🇳 中文</a> · <a href="./es.md">🇪🇸 Español</a> · <a href="./hi.md">🇮🇳 हिन्दी</a><br />
  <a href="./ar.md">🇸🇦 العربية</a> · <a href="./pt-BR.md">🇧🇷 Português</a> · <strong>🇷🇺 Русский</strong> · <a href="./fr.md">🇫🇷 Français</a> · <a href="./id.md">🇮🇩 Bahasa Indonesia</a>
</p>

# shadow-vault (`svault`)

> Стеганография нулевого доверия (Zero-Trust) и двухуровневое зашифрованное хранилище с аппаратной привязкой — скрывайте конфиденциальные файлы внутри обычных PNG/аудио носителей, запечатывайте их с помощью Argon2id + ChaCha20-Poly1305 + Windows DPAPI или встраивайте ложные хранилища с правдоподобным отрицанием (Plausible Deniability) по двум паролям.

[![Build](https://github.com/GHSFS/shadow-vault/actions/workflows/build.yml/badge.svg)](https://github.com/GHSFS/shadow-vault/actions/workflows/build.yml)
[![Tests](https://github.com/GHSFS/shadow-vault/actions/workflows/test.yml/badge.svg)](https://github.com/GHSFS/shadow-vault/actions/workflows/test.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](../../LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20x64-0078D6)](#-быстрый-старт-и-примеры-cli)

</div>

---

## 🛡️ Обзор и ключевые возможности

<details open>
<summary><b>🛡️ Обзор и ключевые возможности</b></summary>
<br>

`shadow-vault` (`svault.exe`) — это автономный криптографический инструментарий и средство стеганографии в едином исполняемом файле на Rust без внешних зависимостей, созданный для специалистов, требующих защиты военного уровня для критически важных файлов (seed-фразы, приватные ключи, учетные данные, конфиденциальные исследовательские отчеты):

1. **Двухуровневое аутентифицированное шифрование (`SVLT` v1/v2)** — сочетает криптографическую функцию выработки ключа с жесткой памятью **Argon2id** + **ChaCha20-Poly1305** AEAD с опциональной привязкой к оборудованию и сеансу пользователя **Windows DPAPI (`CryptProtectData`)**. Даже если злоумышленник физически завладеет файлом `.svault` и паролем, хранилище с привязкой DPAPI невозможно расшифровать вне исходного сеанса пользователя Windows.
2. **Правдоподобное отрицание и ложные хранилища-приманки (`src/decoy.rs`)** — внедряет основной скрытый секрет (открываемый мастер-паролем) и безвредные данные-приманку (открываемые паролем приманки) в один контейнер. Под принуждением ввод пароля приманки расшифровывает только безобидные данные, в то время как основной скрытый слот статистически неотличим от равномерного случайного шума (CSPRNG-заполнение и шифротекст ChaCha20-Poly1305).
3. **Стеганография без потерь в обычных медиафайлах** — скрывает зашифрованные контейнеры внутри повседневных файлов:
   - **Изображения PNG (`embed` / `extract`)**: внедряет вспомогательный чанк `svLt` перед `IEND` с валидными контрольными суммами IEEE 802.3 CRC-32 (поддерживает прямое внедрение ложных хранилищ).
   - **Аудиофайлы WAV (`embed-wav` / `extract-wav`)**: поддерживает подчанки RIFF/WAVE (`--mode chunk`) и замену младшего значащего бита (LSB) 16-битных аудиосэмплов PCM (`--lsb`) с проверкой CRC-32.
   - **Изображения BMP (`src/bmp.rs`)**: LSB-стеганография по несжатым 24-битным каналам RGB с сохранением выравнивания строк по 4 байта и защищенным 12-байтным конвертом (`svLt`, длина, полезная нагрузка, CRC-32).
   - **Аудиофайлы MP3 (`src/mp3/`)**: скрывает полезную нагрузку во фреймах приватных тегов ID3v2.3/ID3v2.4 (`PRIV`) или в межфреймовом заполнении MPEG Audio Layer III с проверкой синхронизации фреймов, сохранением метаданных (TIT2, TPE1) и оценкой емкости.
4. **Универсальная оценка емкости носителя (`capacity`)** — точно рассчитывает общий размер, полезную байтовую емкость и накладные расходы для `.bmp`, `.wav`, `.png` и `.mp3` (`svault capacity <carrier> [--json]`).
5. **Схема разделения секрета Шамира (`M-of-N`, `src/shamir.rs`)** — константно-временная арифметика в конечном поле $\text{GF}(256)$ без условных ветвлений. Разделяет мастер-ключи восстановления, пароли или контейнеры на $N$ долей, требуя любые $M$ для восстановления (`svault split` / `svault combine`). Поддерживает бронированный текст ASCII, компактные строки и JSON.
6. **Аудитор стойкости паролей и энтропии носителей (`src/audit.rs`)** — вычисляет энтропию Шеннона (бит/байт), разнообразие алфавита и выявляет уязвимые шаблоны (повторы, последовательности, шаблоны клавиатуры, leetspeak). Проверяет чанки PNG, потоки WAV RIFF/LSB, 24-битные BMP и контейнеры `.svault` на наличие аномалий (`svault audit <target>` / `svault audit -p <passphrase>`).
7. **Хранилище RFC 6238 TOTP 2FA (`src/totp.rs`)** — локальный двухфакторный аутентификатор без внешних зависимостей, запечатанный в `.svault`. Включает Base32 (RFC 4648), RFC 3174 SHA-1, RFC 2104 HMAC (SHA-1/256/512), парсер `otpauth://totp/...`, константно-временную проверку и визуальный таймер обратного отсчета в консоли (`svault totp add`, `svault totp code`, `svault totp list`, `svault totp verify`).
8. **Автоматически очищаемый буфер обмена (`src/clipboard_guard.rs`)** — безопасно копирует учетные данные в буфер Windows и очищает их по истечении TTL (например, `--clip-ttl 15`). Внедряет форматы приватности Windows 10/11 для блокировки сохранения в журнале (Win + V) и облачной синхронизации, проводя константно-временную сверку отпечатка SHA-256 (`constant_time_eq_32`).
9. **Помехоустойчивая броня Коши Рида-Соломона (`src/armor.rs`)** — добавляет полосы четности и бронированный экспорт/импорт/восстановление ASCII `.svault.asc` для защиты от повреждения битов и сетевых сбоев. Генераторная матрица Коши $[I_K; A]$ над $\text{GF}(256)$ гарантирует свойства MDS: ЛЮБЫЕ $K$ неповрежденных полос из $K+M$ полностью восстанавливают данные (`svault repair`).
10. **Архивация каталогов и манифест файлов (`src/archive.rs`)** — упаковывает деревья каталогов с нормализацией относительных путей, защитой от Zip Slip, защитой от декомпрессионных бомб, проверкой SHA-256 по каждому файлу и сохранением прав доступа в герметичный контейнер `SVLT` (`svault pack-dir` / `svault unpack-dir`).
11. **Двухфакторная аутентификация Keyfile + Пароль (`src/keyfile.rs`)** — объединяет физический USB-токен или внешний файл ключа (`--keyfile <path>`) с паролем пользователя через потоковое предхеширование 64 KiB HMAC-SHA256 перед Argon2id.
12. **Блочное потоковое шифрование (`stream`)** — аутентифицированное потоковое шифрование блоками по 4 MiB с постоянным объемом памяти $O(1)$ для огромных файлов на несколько гигабайт, с защитой ключа через DPAPI и временными политиками.
13. **Отчет о визуальных и статистических различиях стегоносителя (`src/diff.rs`)** — оценивает визуальные искажения (MSE, PSNR, MAE), аудиоискажения (SNR, PSNR) и сдвиг энтропии Шеннона $\Delta H$ (`svault compare <original> <stego>`).
14. **Переключатель «мертвеца» и автоуничтожение при превышении попыток (`src/guard.rs`)** — привязка к защищенному журналу попыток (`.guard`). При $K$ неудачных попытках ввода пароля или истечении срока бездействия запускает 3-этапное криптографическое уничтожение (0x00, 0xFF, CSPRNG) и безвозвратно удаляет файл.
15. **Детерминированный и CSPRNG генератор паролей (`src/passgen/`)** — Diceware BIP-39 на 2 048 слов, генерация паролей без визуально схожих символов (`--exclude-ambiguous`), случайные криптографические байты и детерминированная выработка из мастер-сида (`svault keygen`).
16. **Единый структурированный JSON-вывод (`--json`)** — все команды поддерживают структурированный машиночитаемый JSON для интеграции в CI/CD и скрипты автоматизации.
17. **Ротация ключей контейнера (`rotate`, `src/rotate.rs`)** — атомарно перешифровывает контейнеры и стегоносители с новой солью, Nonce и учетными данными без расшифровки на диск.
18. **Изолированный манифест целостности «Канарейка» (`canary`, `src/canary.rs`)** — создает и верифицирует подписанные списки контрольных сумм SHA-256 с HMAC для мониторинга каталогов.
19. **Стеганография в MP3 ID3v2 и аудиокадрах (`src/mp3/`)** — скрывает данные в файлах MP3 через теги ID3v2 PRIV или межфреймовые зазоры с правдоподобным отрицанием.
20. **Аппаратная привязка FIDO2 / Windows Hello (`src/hardware_token/`)** — связывает ключи шифрования с физическими токенами FIDO2 USB (YubiKey) или биометрией TPM Windows Hello через CTAP2 PRF и Argon2id (`svault fido2`).
21. **Постквантовое гибридное инкапсулирование ключей (`src/pq_kem/`)** — квантово-устойчивое двухуровневое асимметричное запечатывание, сочетающее классический X25519 с NIST FIPS 203 ML-KEM-768 (`svault kem`).
22. **Упреждающее обнуление памяти (`zeroize`)** — очищает промежуточные ключи и открытый текст из памяти байтами 0x00 при выходе из области видимости.

</details>

---

## 🏛️ Архитектура хранения и стеганографии

<details open>
<summary><b>🏛️ Архитектура хранения и стеганографии</b></summary>
<br>

```text
  [ Основной секрет ]   ──▶ [ ChaCha20-Poly1305 + CSPRNG-заполнение ] ──┐ (Скрытый слот)
                                                                         │
  [ Ложные данные ]     ──▶ [ Шифрование ChaCha20-Poly1305 ]          ──┴─▶ Контейнер SVLT v2 (.svault)
                                                                                ├── Прямое сохранение на диск
                                                                                └── Стегоноситель
                                                                                      ├── Изображение PNG (.png)
                                                                                      ├── Аудиофайл WAV (.wav)
                                                                                      ├── Изображение BMP (.bmp)
                                                                                      └── Аудиофайл MP3 (.mp3)
```

</details>

---

## ⚡ Ключевые функции и гарантии безопасности

<details open>
<summary><b>⚡ Ключевые функции и гарантии безопасности</b></summary>
<br>

- **Argon2id + ChaCha20-Poly1305 AEAD** — 128-битная случайная соль, 96-битный Nonce, доменно-разделенная выработка 256-битного ключа и 128-битный аутентификационный тег Poly1305. Любое вмешательство приводит к немедленному отказу в расшифровке.
- **Автоматически очищаемый буфер обмена (`clip`)**:
  - **Прямое взаимодействие с Win32**: прямой вызов API буфера обмена Windows с 10 повторными попытками.
  - **Блокировка истории и облака**: запись служебных форматов Windows 10/11 для исключения из Win+V и облачной синхронизации.
  - **Константно-временная проверка**: побайтовое сравнение SHA-256 (`constant_time_eq_32`) гарантирует очистку только в том случае, если в буфере все еще находятся защищаемые данные.
  - **Визуальный таймер и мгновенная очистка**: динамический прогресс-бар в консоли (`[████████░░] 12s remaining`), мгновенная очистка по нажатию Enter и тихий режим (`--silent`).
  - **Прямая интеграция с командами**: флаги `--clip` и `--clip-ttl <сек>` встроены в `decrypt`, `extract`, `totp code` и др.
- **Хранилище RFC 6238 TOTP 2FA (`totp`)**:
  - **Ноль внешних зависимостей**: полная реализация Base32, SHA-1 и HMAC со 100% прохождением тестов.
  - **Аппаратная привязка и AEAD**: хранение записей в контейнерах `.svault` под двойной защитой Argon2id и DPAPI.
  - **Совместимость с Key URI**: разбор и каноническая сериализация стандартных URI `otpauth://totp/...`.
  - **Защита от атак по времени**: константно-временная сверка кодов с настраиваемым окном погрешности ($\pm S$).
- **Аудитор стойкости паролей и энтропии (`audit`)**:
  - **Вычисление энтропии Шеннона**: $0.0 \le H \le 8.0$ бит на байт и расчет объема пространства ключей.
  - **Выявление уязвимостей**: повторы, последовательности, раскладки клавиатуры и словарные совпадения.
  - **Оценка времени подбора**: онлайн (100/сек), оффлайн Argon2id ($10^3$/сек) и оффлайн GPU-кластеры ($10^{10}$/сек).
  - **Стеганоанализ носителей**: проверка структуры PNG, WAV, BMP LSB и тест равномерности Хи-квадрат ($\chi^2$).
- **Схема разделения секрета Шамира ($M$-из-$N$)**:
  - **Бестабличная арифметика поля**: умножение без ветвлений и обращение по Ферма ($a^{-1} = a^{254}$) в $\text{GF}(256)$.
  - **Двойная целостность**: встроенный хэш SHA-256 секрета и CRC-32 для каждой доли.
- **Контейнеры с правдоподобным отрицанием по двум паролям**:
  - **Прозрачная расшифровка**: разблокировка нужного слота в зависимости от введенного пароля.
  - **Недоказуемый скрытый слот**: отсутствие открытых заголовков; хвост контейнера неотличим от белого шума (~8.0 бит/байт).
  - **Маскирующее заполнение (`--padding <bytes>`)**: случайные байты CSPRNG против анализа длины файла.
- **Аппаратная привязка к сеансу (`--dpapi`)** — шифрование привязывается к текущей учетной записи Windows через DPAPI.
- **Упреждающее обнуление памяти (`zeroize`)** — буферы ключей затираются нулями при освобождении памяти.
- **Стеганография PNG без потерь (`embed` / `extract`)** — внедрение блока `svLt` с CRC-32 и поддержкой ложных хранилищ.
- **Стеганография в аудиофайлах WAV (`embed-wav` / `extract-wav`)**:
  - **Режим RIFF-подчанка (`--mode chunk`)**: добавление метаданных `svLt` с CRC-32.
  - **Режим 16-бит PCM LSB (`--lsb`)**: изменение младшего бита без влияния на восприятие звука.
- **LSB-стеганография в 24-битных BMP (`embed-bmp` / `extract-bmp`)**:
  - **Сохранение выравнивания строк**: учет 4-байтового шага и внедрение только в каналы R, G, B.
  - **Защитный конверт на 12 байт**: формат `[svLt: 4B][len: 4B LE][payload: NB][crc32: 4B LE]`.
- **Помехоустойчивая броня Коши Рида-Соломона (`armor` / `dearmor` / `repair`)**:
  - **MDS-кодирование над $\text{GF}(256)$**: матрица $[I_K; A]$. Любые $K$ неповрежденных полос восстанавливают все данные.
  - **Контроль CRC-32 по полосам и SHA-256 контейнера**: локализация ошибок и проверка целостности.
  - **Самовосстановление**: автоматическая регенерация данных в `repair` и `dearmor`.
- **Архивация каталогов (`pack-dir` / `unpack-dir`)**:
  - **Бинарный формат `SVAR`**: заголовок 18 байт, индивидуальные хэши SHA-256 и контрольная сумма CRC-32.
  - **Защита от Zip Slip**: отклонение относительных путей `..` и зарезервированных имен устройств Windows.
  - **Защита от архивных бомб**: порог до 8 ГиБ на архив и 4 ГиБ на отдельный файл.
- **Оценка емкости носителей (`capacity`)** — расчет полезного объема для `.bmp`, `.wav`, `.png`, `.mp3`.
- **Просмотр заголовков с нулевым знанием (`inspect`)** — отображение версии, соли и флагов без расшифровки.
- **Временные политики блокировки и истечения (`policy`)**:
  - **Аутентифицированный заголовок (`SVPO`)**: 28 канонических байт с отметками времени и CRC-32.
  - **Привязка к AAD**: изменение дат приводит к сбою аутентификации Poly1305.
- **Ключевой файл + Пароль (`keyfile`)** — 64 KiB буфер для USB-ключей с передачей 256-битного сида в Argon2id.
- **Потоковое блочное шифрование (`stream`)** — память $O(1)$ для файлов объемом в десятки гигабайт.
- **Анализ различий стегоносителей (`compare`)** — метрики искажений MSE, PSNR, SNR и сдвиг энтропии $\Delta H$.
- **Автоуничтожение и таймер «мертвеца» (`guard`)** — 3-этапное затирание при превышении ошибок ввода пароля или неактивности.
- **Детерминированный генератор паролей (`keygen`)** — фразы BIP-39 Diceware, символьные пароли и токены.
- **Интерактивная консоль в памяти (`repl`)** — работа с хранилищем ключ-значение в ОЗУ с защитой буфера обмена.
- **Безопасное 3-проходное уничтожение (`shred`)** — перезапись файлов байтами `0x00`, `0xFF` и шумом перед удалением.
- **Единый статический бинарный файл** — скомпилирован без внешних зависимостей среды исполнения.

</details>

---

## 🚀 Быстрый старт и примеры CLI

<details open>
<summary><b>🚀 Быстрый старт и примеры CLI (Нажмите на категорию, чтобы свернуть / развернуть)</b></summary>
<br>

<details open>
<summary><b>🔐 1. Двухуровневое шифрование и ложные хранилища с правдоподобным отрицанием (#1 - #6)</b></summary>
<br>

```bash
# 1. Зашифровать файл с паролем и аппаратной привязкой к Windows DPAPI
svault encrypt -i wallet-seed.txt -o wallet.svault -p "your-strong-passphrase" --dpapi

# 2. Зашифровать контейнер с правдоподобным отрицанием (основной секрет + ложная приманка)
svault encrypt -i classified.txt --decoy shopping-list.txt -o deniable.svault \
  -p "primary-secret-pass" --decoy-passphrase "decoy-harmless-pass" --padding 512

# 3. Расшифровать контейнер с отрицанием (пароль приманки выдает только безобидные данные)
svault decrypt -i deniable.svault -o revealed.txt -p "decoy-harmless-pass"
# Основной пароль восстанавливает подлинный секретный файл
svault decrypt -i deniable.svault -o restored.txt -p "primary-secret-pass"

# 4. Просмотреть метаданные контейнера без расшифровки (.svault, .png, .wav или .bmp)
svault inspect deniable.svault

# 5. Скрыть ложное хранилище с двумя паролями прямо внутри изображения PNG
svault embed -c wallpaper.png -s classified.txt --decoy shopping-list.txt -o wallpaper-stego.png \
  -p "primary-secret-pass" --decoy-passphrase "decoy-harmless-pass"

# 6. Извлечь секрет из изображения PNG (по основному паролю или паролю приманки)
svault extract -c wallpaper-stego.png -o restored-seed.txt -p "primary-secret-pass"
svault extract -c wallpaper-stego.png -o decoy-seed.txt --decoy-passphrase "decoy-harmless-pass"
```

</details>

<details open>
<summary><b>🖼️ 2. Стеганография в медиафайлах: PNG, WAV, BMP, MP3 и оценка емкости (#7 - #13)</b></summary>
<br>

```bash
# 7. Скрыть секрет в аудиофайле WAV (через подчанк RIFF или LSB 16-битных сэмплов)
svault embed-wav -c track.wav -s classified.txt -o track-lsb.wav -p "primary-secret-pass" --lsb

# 8. Извлечь и расшифровать секрет из файла WAV (автоопределение формата)
svault extract-wav -c track-lsb.wav -o restored-audio.txt -p "primary-secret-pass"

# 9. Оценить полезную емкость носителя для стеганографии (.bmp, .wav, .png или .mp3)
svault capacity landscape.bmp
svault capacity track.wav --json
svault capacity song.mp3

# 10. Скрыть секрет в 24-битном изображении BMP методом LSB по пикселям
svault embed-bmp -c landscape.bmp -s classified.txt -o landscape-stego.bmp -p "primary-secret-pass"

# 11. Извлечь секрет из изображения BMP сразу в защищенный буфер обмена (очистка через 15 сек)
svault extract-bmp -c landscape-stego.bmp -p "primary-secret-pass" --clip --clip-ttl 15

# 12. Скрыть секрет в аудиофайле MP3 (через тег ID3v2 PRIV или межфреймовое заполнение)
svault embed-mp3 -c song.mp3 -s classified.txt -o song-stego.mp3 -p "primary-secret-pass" --mode id3v2
svault embed-mp3 -c song.mp3 -s classified.txt -o song-frame.mp3 -p "primary-secret-pass" --mode frame

# 13. Извлечь секрет из файла MP3 (автоопределение режима)
svault extract-mp3 -c song-stego.mp3 -o restored-mp3.txt -p "primary-secret-pass"
```

</details>

<details open>
<summary><b>🧩 3. Безопасное уничтожение, разделение Шамира и аудит энтропии (#12 - #16)</b></summary>
<br>

```bash
# 12. Безопасно уничтожить исходный файл открытого текста (в 3 прохода)
svault shred classified.txt --passes 3

# 13. Разделить мастер-ключ восстановления на 3-из-5 долей по схеме Шамира
svault split -s "your-master-seed-or-secret" -m 3 -n 5 -o shares/share

# 14. Объединить любые 3 доли для полного восстановления исходного секрета
svault combine shares/share_1.share shares/share_3.share shares/share_5.share -o restored.txt

# 15. Провести аудит стойкости пароля, энтропии Шеннона и времени подбора
svault audit -p "Correct-Horse-Battery-Staple-2026!"

# 16. Проверить стегоноситель или контейнер на наличие скрытых полезных данных
svault audit wallpaper-stego.png --json
```

</details>

<details open>
<summary><b>⏱️ 4. Хранилище RFC 6238 TOTP 2FA и защита буфера обмена (#17 - #23)</b></summary>
<br>

```bash
# 17. Добавить запись TOTP 2FA по ключу Base32 или ссылке otpauth://
svault totp add github --secret "JBSWY3DPEHPK3PXP" --issuer "GitHub" --vault totp.svault -p "vault-pass"
svault totp add --uri "otpauth://totp/Google:alice?secret=JBSWY3DPEHPK3PXP&issuer=Google" --vault totp.svault -p "vault-pass"

# 18. Сгенерировать текущий одноразовый код 2FA с индикатором времени (или --json)
svault totp code github --vault totp.svault -p "vault-pass"
svault totp code github --vault totp.svault -p "vault-pass" --json

# 19. Проверить код OTP с допустимым окном временного сдвига (+/- 1 шаг)
svault totp verify github 123456 --skew 1 --vault totp.svault -p "vault-pass"

# 20. Вывести список записей 2FA и экспортировать их
svault totp list --vault totp.svault -p "vault-pass"
svault totp export github --vault totp.svault -p "vault-pass"

# 21. Скопировать секрет в буфер обмена с автоочисткой через 15 сек (или в тихом режиме)
svault clip copy "my-super-secret-password" --ttl 15
svault clip copy "my-super-secret-password" --ttl 15 --silent

# 22. Проверить состояние буфера и служебные метаданные или очистить его вручную
svault clip status
svault clip clear

# 23. Расшифровать данные напрямую в защищенный буфер без вывода на экран и диск
svault decrypt -i secret.svault -p "vault-pass" --clip --clip-ttl 30
svault totp code github --vault totp.svault -p "vault-pass" --clip --clip-ttl 15
```

</details>

<details open>
<summary><b>🛡️ 5. Броня Коши Рида-Соломона и архивация каталогов (#24 - #30)</b></summary>
<br>

```bash
# 24. Защитить контейнер .svault броней ASCII с полосами четности Рида-Соломона (.svault.asc)
svault armor -i secret.svault -o secret.svault.asc -k 4 -m 2

# 25. Преобразовать бронированный файл ASCII обратно в бинарный контейнер .svault
svault dearmor -i secret.svault.asc -o recovered.svault

# 26. Восстановить поврежденный файл .svault.asc с помощью полос четности Коши
svault repair -i corrupted.svault.asc -o repaired.svault.asc --json
svault repair -i corrupted.svault.asc -o direct_recovered.svault --binary

# 27. Проверить состояние полос и целостность бронированного контейнера
svault inspect secret.svault.asc
svault audit secret.svault.asc --json

# 28. Упаковать все дерево каталогов в зашифрованный архивный контейнер .svault
svault pack-dir -i ./my_project -o project.svault -p "pack-passphrase" --list

# 29. Упаковать каталог прямо в стегоноситель (PNG, WAV, BMP, MP3) или броню ASCII
svault pack-dir -i ./my_project -o project.png -p "pack-passphrase" --carrier cover.png
svault pack-dir -i ./my_project -o project.svault.asc -p "pack-passphrase" --armor

# 30. Распаковать каталог, просмотреть манифест или предварительно сверить контрольные суммы
svault unpack-dir -i project.svault -p "pack-passphrase" --list
svault unpack-dir -i project.svault -p "pack-passphrase" --verify-only
svault unpack-dir -i project.svault -o ./restored_project -p "pack-passphrase" --overwrite
```

</details>

<details open>
<summary><b>⏳ 6. Временные политики, USB-ключи Keyfile и блочный стриминг (#31 - #42)</b></summary>
<br>

```bash
# 31. Зашифровать с политикой блокировки по времени (невозможно открыть до указанной даты)
svault encrypt -i escrow.txt -o escrow.svault -p "vault-pass" --not-before "2026-12-31T00:00:00Z" --policy-desc "Year-End Escrow"

# 32. Зашифровать с политикой автоистечения (сгорает через 2 часа или в указанную дату)
svault encrypt -i token.txt -o token.svault -p "vault-pass" --expires-in 2h --policy-desc "Session Token"
svault encrypt -i doc.txt -o doc.svault -p "vault-pass" --expires-at "2026-10-15"

# 33. Просмотреть метаданные политики без расшифровки (в консоли и JSON)
svault inspect escrow.svault
svault inspect escrow.svault --json

# 34. Проверить расшифровку относительно конкретной опорной даты
svault decrypt -i escrow.svault -o restored.txt -p "vault-pass" --at-time "2027-01-01"

# 35. Сгенерировать криптографический аппаратный USB-ключ (CSPRNG, по умолчанию 64 байта)
svault keyfile generate -o usb_token.key --bytes 64

# 36. Проверить отпечаток и энтропию Шеннона ключевого файла (в консоли и JSON)
svault keyfile inspect usb_token.key
svault keyfile inspect usb_token.key --json
svault keyfile fingerprint usb_token.key

# 37. Зашифровать и расшифровать с 2FA (Пароль + Ключевой файл)
svault encrypt -i secret.txt -o sealed.svault -p "master-pass" -k usb_token.key
svault decrypt -i sealed.svault -o restored.txt -p "master-pass" -k usb_token.key

# 38. Шифрование только по ключевому файлу без ввода пароля
svault encrypt -i token.txt -o hardware.svault -k usb_token.key
svault decrypt -i hardware.svault -o restored.txt -k usb_token.key

# 39. Упаковать каталог в зашифрованное хранилище с 2FA по ключевому файлу
svault pack-dir -i ./confidential -o archive.svault -p "pack-pass" -k usb_token.key
svault unpack-dir -i archive.svault -o ./unpacked -p "pack-pass" -k usb_token.key

# 40. Зашифровать многогигабайтный файл блочным стримингом (блоки по 4 MiB)
svault stream encrypt -i large_dataset.iso -o large_dataset.svault -p "stream-pass"
svault encrypt -i database.backup -o db.svault -p "stream-pass" --stream --chunk-size 8M

# 41. Расшифровать потоковый контейнер (автоопределение формата SVST)
svault decrypt -i large_dataset.svault -o restored.iso -p "stream-pass"
svault stream decrypt -i db.svault -o restored_db.backup -p "stream-pass"

# 42. Просмотреть метаданные потокового контейнера без расшифровки
svault stream inspect large_dataset.svault
svault inspect large_dataset.svault --json
```

</details>

<details open>
<summary><b>🚨 7. Отчеты о различиях стего, автоуничтожение и генерация паролей (#43 - #53)</b></summary>
<br>

```bash
# 43. Сравнить исходный носитель со стегоносителем (PNG, BMP, WAV или бинарный файл)
svault compare cover.bmp stego.bmp
svault compare cover.png stego.png --json
svault diff original.wav stego.wav --detailed

# 44. Активировать защиту хранилища с самоуничтожением за 3 ошибки и таймером неактивности
svault encrypt -i secret.txt -o guarded.svault -p "vault-pass" --max-attempts 3 --dead-man 7d --guard-companion

# 45. Напрямую активировать защиту существующего носителя или контейнера
svault guard arm -t stego.png --max-attempts 3 --companion
svault guard arm -t vault.svault --max-attempts 5 --dead-man 24h

# 46. Проверить статус защиты и число оставшихся попыток (в консоли и JSON)
svault guard status -t guarded.svault
svault guard status -t guarded.svault --json

# 47. Подтвердить присутствие для продления таймера «мертвеца» или сбросить счетчик ошибок
svault guard checkin -t guarded.svault --interval 30d
svault guard reset -t guarded.svault

# 48. Снять защиту или экстренно запустить многопроходное безвозвратное уничтожение
svault guard disarm -t guarded.svault
svault guard trigger -t guarded.svault --force --passes 3

# 49. Сгенерировать парольную фразу Diceware BIP-39 из 6 слов
svault keygen --words 6

# 50. Сгенерировать фразу Diceware с цифрами и заглавными буквами
svault keygen --words 4 --separator "." --capitalize --number

# 51. Сгенерировать 24-значный пароль с фильтром неоднозначных символов и оценкой энтропии
svault keygen --length 24 --exclude-ambiguous --entropy

# 52. Детерминированная генерация пароля из мастер-сида и контекста сервиса
svault keygen --words 6 --seed "master-recovery-seed" --context "github-token"

# 53. Сгенерировать криптографический случайный токен на 32 байта и скопировать в буфер
svault keygen --bytes 32 --base64 --clip --clip-ttl 30
svault keygen --bytes 20 --base32 --json
```

</details>

<details open>
<summary><b>💻 8. Ротация ключей, целостность «Канарейка» и интерактивный REPL (#54 - #63)</b></summary>
<br>

```bash
# 54. Перешифровать контейнер с новым паролем, солью и свежим Nonce
svault rotate -i vault.svault -o rotated.svault -p "old-secret" -n "new-secret"

# 55. Атомарно перешифровать контейнер или стегоноситель на месте (In-Place)
svault rotate -i vault.svault --in-place -p "old-secret" -n "new-secret"
svault rotate -i stego.bmp --in-place -p "old-pass" -n "new-pass"

# 56. Перешифровать учетные данные в стегоносителе (PNG, WAV, BMP или броне ASCII)
svault rotate -i carrier.png -o rotated.png -p "old-pass" -n "new-pass"
svault rotate -i carrier.asc -o rotated.asc -p "old-pass" -n "new-pass"

# 57. Перешифровать с переключением привязки к оборудованию DPAPI или сбросом политик
svault rotate -i vault.svault -o dpapi_vault.svault -p "old-pass" -n "new-pass" --dpapi
svault rotate -i locked.svault -o unlocked.svault -p "old-pass" -n "new-pass" --clear-policy --json

# 58. Инициализировать изолированный манифест целостности «Канарейка» для каталога
svault canary init -d ./vaults
svault canary init -d ./vaults -p "canary-auth-secret" --json

# 59. Проверить целостность файлов на диске относительно манифеста «Канарейка»
svault canary verify -d ./vaults
svault canary verify -d ./vaults -p "canary-auth-secret" --strict --json

# 60. Запустить интерактивную консоль REPL для работы с хранилищем ключ-значение в ОЗУ
svault repl -v myvault.svault -p "session-pass"

# 61. Пакетно выполнить команды REPL в неинтерактивном режиме через --exec
svault repl -v myvault.svault -p "session-pass" --exec "set api_key sk_live_xyz --tag prod; set db_pass secret; save"

# 62. Запросить секрет с защитой через автоматически очищаемый буфер обмена
svault repl -v myvault.svault -p "session-pass" --exec "get api_key --clip --clip-ttl 15"

# 63. Открыть REPL в режиме «только для чтения» или экспортировать записи в JSON
svault repl -v myvault.svault -p "session-pass" --readonly --exec "list" --json
svault repl -v myvault.svault -p "session-pass" --exec "export ./backup.json; exit"
```

</details>

<details open>
<summary><b>🔑 9. Привязка аппаратных ключей FIDO2 / Windows Hello (#64 - #70)</b></summary>
<br>

```bash
# 64. Проверить поддержку аппаратных токенов на платформе (Windows Hello, WebAuthn API, USB HID)
svault fido2 status
svault fido2 status --json

# 65. Зарегистрировать USB-ключ FIDO2 или биометрические данные Windows Hello
svault fido2 enroll yubikey-5c --type usb --user alice --output ./yubikey.json
svault fido2 enroll hello-tpm --type hello --pin 849201 --json

# 66. Протестировать аутентификацию и проверить отпечаток выработки PRF
svault fido2 test ./yubikey.json
svault fido2 test ./yubikey.json --json

# 67. Зашифровать контейнер с привязкой к аппаратному токену FIDO2 и паролем
svault encrypt -i secret.txt -o sealed.svault --fido2-cred ./yubikey.json -p "master-pass"

# 68. Расшифровать контейнер с помощью зарегистрированного аппаратного токена
svault decrypt -i sealed.svault -o restored.txt --fido2-cred ./yubikey.json -p "master-pass"

# 69. Многофакторная аутентификация 2FA: Ключевой файл + токен FIDO2 (без пароля)
svault encrypt -i secret.txt -o mfa.svault -k usb_token.key --fido2-cred ./yubikey.json
svault decrypt -i mfa.svault -o restored.txt -k usb_token.key --fido2-cred ./yubikey.json

# 70. Перешифровать существующий контейнер для добавления или удаления привязки FIDO2
svault rotate -i sealed.svault --in-place -p "old-pass" -n "new-pass" --fido2 --fido2-cred ./yubikey.json
svault rotate -i sealed.svault --in-place -p "new-pass" -n "plain-pass" --no-fido2 --fido2-cred ./yubikey.json
```

</details>

<details open>
<summary><b>⚛️ 10. Постквантовое гибридное инкапсулирование ключей (X25519 + ML-KEM-768) (#71 - #74)</b></summary>
<br>

```bash
# 71. Сгенерировать пару постквантовых гибридных ключей (X25519 + ML-KEM-768)
svault kem keygen -p recipient.pub -s recipient.key
svault kem keygen -p recipient.pub -s recipient.key --json

# 72. Запечатать конфиденциальный файл для открытого ключа получателя (бинарно или ASCII)
svault kem seal -i classified.txt -o sealed.svault.pq -k recipient.pub
svault kem seal -i classified.txt -o sealed.asc -k recipient.pub --armor --json

# 73. Просмотреть метаданные постквантового контейнера (размер шифротекста ML-KEM, CRC-32)
svault kem inspect -i sealed.svault.pq
svault kem inspect -i sealed.asc --json

# 74. Распечатать и расшифровать постквантовое хранилище приватным ключом получателя
svault kem open -i sealed.svault.pq -o restored.txt -k recipient.key
svault kem open -i sealed.asc -o restored.txt -k recipient.key --json
```

</details>

</details>

---

## 🔒 Безопасность памяти и защитные инварианты

<details open>
<summary><b>🔒 Безопасность памяти и защитные инварианты</b></summary>
<br>

- **100% безопасный Rust и константно-временная криптография**: В путях обработки криптографических данных нет блоков `unsafe`; бестабличные вычисления в полях Галуа полностью исключают атаки по времени.
- **Упреждающее затирание памяти**: Промежуточные ключевые расписания, буферы открытого текста и сиды PRF затираются нулями в памяти при уничтожении объектов через `zeroize`.
- **Аппаратная привязка**: Опциональное связывание с Windows DPAPI гарантирует, что шифротекст невозможно расшифровать вне машины и учетной записи, где он был создан.
- **Защита от Zip Slip и декомпрессионных бомб**: Нормализация путей, жесткие ограничения по глубине вложенности и лимиты на выделение памяти исключают отказ в обслуживании.

</details>

---

## 📄 Лицензия и авторские права

<details open>
<summary><b>📄 Лицензия и авторские права</b></summary>
<br>

Авторские права 2026 **GHSFS** ([https://github.com/GHSFS](https://github.com/GHSFS)).

Лицензировано на условиях **Apache License, Version 2.0** ([`LICENSE`](../../LICENSE)).
В соответствии с разделом 4(d) лицензии Apache License 2.0, любое распространение или производные работы должны сохранять уведомления об авторстве, указанные в файле [`NOTICE`](../../NOTICE).

</details>
