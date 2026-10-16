<div align="center">

<p align="center">
  <a href="../../README.md">🇺🇸 English</a> · <a href="./ko.md">🇰🇷 한국어</a> · <a href="./zh-CN.md">🇨🇳 中文</a> · <a href="./es.md">🇪🇸 Español</a> · <a href="./hi.md">🇮🇳 हिन्दी</a><br />
  <strong>🇸🇦 العربية</strong> · <a href="./pt-BR.md">🇧🇷 Português</a> · <a href="./ru.md">🇷🇺 Русский</a> · <a href="./fr.md">🇫🇷 Français</a> · <a href="./id.md">🇮🇩 Bahasa Indonesia</a>
</p>

# shadow-vault (`svault`)

> خزانة مشفرة بدون ثقة مع إخفاء البيانات والربط بالأجهزة مزدوج الطبقة — إخفاء الملفات الحساسة داخل ملفات PNG/الصوت العادية، وإحكام إغلاقها باستخدام Argon2id + ChaCha20-Poly1305 + Windows DPAPI، أو تضمين خزائن تمويهية ذات إنكار معقول بكلمة مرور مزدوجة.

[![Build](https://github.com/GHSFS/shadow-vault/actions/workflows/build.yml/badge.svg)](https://github.com/GHSFS/shadow-vault/actions/workflows/build.yml)
[![Tests](https://github.com/GHSFS/shadow-vault/actions/workflows/test.yml/badge.svg)](https://github.com/GHSFS/shadow-vault/actions/workflows/test.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](../../LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20x64-0078D6)](#البدء-السريع)

</div>

---

### نظرة عامة على المشروع

`shadow-vault` (`svault.exe`) هي أداة تشفير وإخفاء بيانات قائمة بذاتها ومكتوبة بلغة Rust بدون أي تبعيات خارجية، مصممة لحماية البيانات الحساسة للغاية:

1. **تشفير موثق ثنائي الطبقة (`SVLT` v1/v2)** — يجمع بين اشتقاق المفاتيح بواسطة **Argon2id** المقاوم لهجمات الذاكرة وتشفير **ChaCha20-Poly1305** AEAD، مع ربط اختياري بالعتاد عبر **Windows DPAPI (`CryptProtectData`)**.
2. **الإنكار المعقول والخزائن التمويهية (`src/decoy.rs`)** — تضمين كل من البيانات السرية الأساسية والبيانات التمويهية في حاوية واحدة؛ تحت الإكراه، تفتح كلمة مرور التمويه البيانات غير الضارة فقط.
3. **إخفاء البيانات غير المضيع في الوسائط**:
   - **صور PNG**: حقن كتلة `svLt` الإضافية قبل `IEND` مع التحقق بواسطة CRC-32.
   - **ملفات WAV**: دعم كتل RIFF وتعديل البت الأقل أهمية (LSB) في عينات 16-بت PCM.
   - **صور BMP**: تعديل LSB في قنوات RGB 24-بت مع الحفاظ على محاذاة 4 بايت.
   - **ملفات MP3**: إخفاء البيانات داخل إطارات ID3v2 `PRIV` أو حشو إطارات MPEG.
4. **تقدير السعة الشامل للوسائط (`capacity`)** — حساب السعة المتاحة في `.bmp` و`.wav` و`.png` و`.mp3`.
5. **مشاركة أسرار شامير (`M-من-N`, `src/shamir.rs`)** — خوارزمية بزمن ثابت على $\text{GF}(256)$ لتقسيم المفاتيح إلى $N$ حصة مع عتبة استعادة $M$.
6. **مدقق قوة كلمات المرور والإنتروبيا (`src/audit.rs`)** — حساب إنتروبيا شانون واكتشاف الأنماط الضعيفة.
7. **خزينة TOTP 2FA القياسية (`src/totp.rs`)** — مولد مصادقة ثنائية مستقل ومحمي ضد هجمات التوقيت.
8. **حارس الحافظة ذو انتهاء الصلاحية التلقائي (`src/clipboard_guard.rs`)** — حظر سجل Windows 10/11 والمسح التلقائي بعد فترة TTL محددة.
9. **درع تصحيح الأخطاء كوشي ريد-سولومون (`src/armor.rs`)** — مصفوفة كوشي على $\text{GF}(256)$ تتيح استعادة البيانات كاملة من أي $K$ أجزاء سليمة من أصل $K+M$.
10. **حزم المجلدات والملفات المتعددة (`src/archive.rs`)** — حماية ضد ثغرات Zip Slip / Zip Bomb وتوثيق كل ملف ببصمة SHA-256.
11. **اشتقاق 2FA باستخدام ملف مفتاح (`src/keyfile.rs`)** — ربط التوكنات المادية بمفتاح USB مع تجزئة مسبقة عبر HMAC-SHA256.
12. **تشفير التدفق المستمر (`src/stream.rs`)** — معالجة كتل 4 MiB في ذاكرة ثابتة $O(1)$ للملفات الضخمة.
13. **تقرير الفروق البصرية والإحصائية (`src/diff.rs`)** — تقييم مقاييس MSE و PSNR و SNR وانحراف الإنتروبيا.
14. **زر الرجل الميت والإتلاف الذاتي (`src/guard.rs`)** — إتلاف تشفيري للملف في 3 مراحل بعد $K$ محاولات خاطئة متتالية.
15. **مولد كلمات المرور BIP-39 و CSPRNG (`src/passgen/`)** — إنشاء عبارات استرداد من قاموس 2,048 كلمة.
16. **مخرجات JSON موحدة المهيكلة (`--json`)** — جاهزة للدمج في مسارات CI/CD والبرمجة النصية.
17. **تدوير مفاتيح الحاويات (`rotate`)** — إعادة التشفير بأمان وتجديد الملح والنونس دون كتابة نصوص واضحة على القرص.
18. **كناري التحقق من السلامة (`canary`)** — فحص ومراقبة سلامة أشجار الملفات ضد التلاعب.
19. **ربط عتاد FIDO2 و Windows Hello (`src/hardware_token/`)** — دعم مفاتيح YubiKey والمصادقة الحيوية TPM عبر CTAP2 PRF.
20. **التغليف الهجين المقاوم للحوسبة الكمومية (`src/pq_kem/`)** — يجمع بين خوارزمية X25519 ومعيار NIST FIPS 203 ML-KEM-768.
21. **تصفير الذاكرة النشط (`zeroize`)** — مسح المخازن المؤقتة الحساسة في الذاكرة فور الانتهاء منها.

### البدء السريع

```bash
# 1. تشفير ملف بكلمة مرور وربط عتاد DPAPI
svault encrypt -i wallet-seed.txt -o wallet.svault -p "your-strong-passphrase" --dpapi

# 2. إنشاء حاوية إنكار معقول (بيانات سرية + بيانات تمويهية)
svault encrypt -i classified.txt --decoy shopping-list.txt -o deniable.svault \
  -p "primary-secret-pass" --decoy-passphrase "decoy-harmless-pass" --padding 512

# 3. فك التشفير بكلمة المرور التمويهية (يظهر فقط الملف التمويهي)
svault decrypt -i deniable.svault -o revealed.txt -p "decoy-harmless-pass"

# 4. فحص بيانات الحاوية الوصفية بدون فك التشفير
svault inspect deniable.svault

# 5. إخفاء الخزانة داخل صورة PNG
svault embed -c wallpaper.png -s classified.txt --decoy shopping-list.txt -o wallpaper-stego.png \
  -p "primary-secret-pass" --decoy-passphrase "decoy-harmless-pass"

# 6. استخراج البيانات السرية الحقيقية من صورة PNG
svault extract -c wallpaper-stego.png -o restored-seed.txt -p "primary-secret-pass"
```

### الترخيص وحقوق الملكية

Copyright 2026 **GHSFS** ([https://github.com/GHSFS](https://github.com/GHSFS)).

مرخص بموجب **Apache License, Version 2.0** ([LICENSE](../../LICENSE)). يجب الحفاظ على إشعارات الإسناد الواردة في [NOTICE](../../NOTICE).
