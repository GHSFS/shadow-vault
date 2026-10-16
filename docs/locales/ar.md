<div align="center">

<p align="center">
  <a href="../../README.md">🇺🇸 English</a> · <a href="./ko.md">🇰🇷 한국어</a> · <a href="./zh-CN.md">🇨🇳 中文</a> · <a href="./es.md">🇪🇸 Español</a> · <a href="./hi.md">🇮🇳 हिन्दी</a><br />
  <strong>🇸🇦 العربية</strong> · <a href="./pt-BR.md">🇧🇷 Português</a> · <a href="./ru.md">🇷🇺 Русский</a> · <a href="./fr.md">🇫🇷 Français</a> · <a href="./id.md">🇮🇩 Bahasa Indonesia</a>
</p>

# shadow-vault (`svault`)

> إخفاء بيانات انعدام الثقة (Zero-Trust Steganography) وخزينة مشفرة مرتبطة بالعتاد ثنائية الطبقة — إخفاء الملفات الحساسة داخل وسائط PNG/صوتية عادية، وختمها بـ Argon2id + ChaCha20-Poly1305 + Windows DPAPI، أو تضمين خزائن طُعم ذات إنكار معقول بكلمة مرور مزدوجة.

[![Build](https://github.com/GHSFS/shadow-vault/actions/workflows/build.yml/badge.svg)](https://github.com/GHSFS/shadow-vault/actions/workflows/build.yml)
[![Tests](https://github.com/GHSFS/shadow-vault/actions/workflows/test.yml/badge.svg)](https://github.com/GHSFS/shadow-vault/actions/workflows/test.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](../../LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20x64-0078D6)](#-البدء-السريع-ومسارات-عمل-واجهة-السطر-الأوامر-cli)

</div>

---

## 🛡️ نظرة عامة والقدرات الأساسية

<details open>
<summary><b>🛡️ نظرة عامة والقدرات الأساسية</b></summary>
<br>

`shadow-vault` (`svault.exe`) هو صندوق أدوات تشفير وإخفاء بيانات ثنائي فردي مكتوب بلغة Rust وبدون أي تبعيات خارجية، مصمم للمشغلين الذين يحتاجون إلى حماية عسكرية للملفات عالية القيمة (عبارات الاسترداد، المفاتيح الخاصة، أوراق الاعتماد، الملاحظات البحثية السرية):

1. **تشفير موثق ثنائي الطبقة (`SVLT` v1/v2)** — يجمع بين اشتقاق المفاتيح المقوى بالذاكرة **Argon2id** و **ChaCha20-Poly1305** AEAD مع ربط اختياري بعتاد/جلسة مستخدم **Windows DPAPI (`CryptProtectData`)**. حتى لو سرق المهاجم ملف `.svault` وكلمة المرور، لا يمكن فك تشفير الخزينة المرتبطة بـ DPAPI خارج حساب مستخدم Windows الأصلي.
2. **الإنكار المعقول وخزائن الطُعم (`src/decoy.rs`)** — يدمج كلاً من السر الأساسي المخفي (المفتوح بكلمة المرور الرئيسية) وحمولة الطُعم غير الضارة (المفتوحة بكلمة مرور الطُعم) داخل حاوية واحدة. تحت الإكراه، يكشف تقديم كلمة مرور الطُعم عن بيانات الطُعم فقط، بينما تظل الفتحة المخفية الرئيسية غير قابلة للتمييز إحصائياً عن الضجيج العشوائي المنتظم (حشوة CSPRNG ونص مشفر بـ ChaCha20-Poly1305).
3. **إخفاء بيانات في الوسائط دون فقدان الجودة** — يخفي الحاويات المشفرة داخل وسائط الوسائط اليومية:
   - **صور PNG (`embed` / `extract`)**: يحقن مقطعاً إضافياً خاصاً `svLt` قبل `IEND` مع مجاميع فحص CRC-32 متوافقة مع معيار IEEE 802.3 (يدعم التضمين المباشر لخزائن الطُعم).
   - **ملفات الصوت WAV (`embed-wav` / `extract-wav`)**: يدعم نمط مقطع RIFF/WAVE الفرعي (`--mode chunk`) واستبدال البت الأقل أهمية (LSB) لعينات صوت PCM بدقة 16 بت (`--lsb`) مع فحص CRC-32.
   - **صور BMP (`src/bmp.rs`)**: يغير البتات الأقل أهمية (LSB) عبر قنوات بكسل RGB غير المضغوطة بدقة 24 بت مع الحفاظ الصارم على حشوة الصف المكونة من 4 بايت وتضمين مظروف سري مانع للتلاعب مكون من 12 بايت (`svLt`، الطول، الحمولة، CRC-32).
   - **ملفات الصوت MP3 (`src/mp3/`)**: يخفي الحمولات المشفرة داخل إطارات علامات ID3v2.3/ID3v2.4 الخاصة (`PRIV`) أو حشوة ما بين إطارات MPEG Audio Layer III مع التحقق من مزامنة الإطارات والحفاظ على البيانات الوصفية (TIT2, TPE1) وتقدير السعة.
4. **تقدير سعة الناقل الشامل (`capacity`)** — يحسب بدقة الحجم الكلي وسعة البايتات الفعلية القابلة للاستخدام والحمل الإضافي في الناقلات `.bmp` و `.wav` و `.png` و `.mp3` (`svault capacity <carrier> [--json]`).
5. **مشاركة سر شامير (`M-of-N`، `src/shamir.rs`)** — حسابات حقل منتهٍ $\text{GF}(256)$ في زمن ثابت وبدون تفرع شرطي. يقسم مفاتيح الاسترداد أو كلمات المرور أو الحاويات إلى $N$ حصة تتطلب أي $M$ منها لإعادة البناء (`svault split` / `svault combine`). يدعم النصوص المدرعة والترميز في سطر واحد و JSON والتحقق بـ SHA-256/CRC-32.
6. **مدقق قوة كلمة المرور وإنتروبيا الناقل (`src/audit.rs`)** — يحلل مرونة كلمة المرور عبر إنتروبيا شانون (بتات/بايت) وتنوع الأحرف والأنماط الضعيفة (تكرار الأحرف، التسلسلات، مسارات لوحة المفاتيح، قواميس leetspeak). يفحص مقاطع PNG وتدفقات WAV RIFF/LSB و LSB لبكسلات BMP وحاويات `.svault` لرصد التلاعب والتناقضات (`svault audit <target>` / `svault audit -p <passphrase>`).
7. **خزينة RFC 6238 TOTP 2FA (`src/totp.rs`)** — مستودع محلي مشفر للمصادقة الثنائية دون تبعيات خارجية، مختوم داخل حاويات `.svault`. يشمل مرمز Base32 (RFC 4648)، RFC 3174 SHA-1، RFC 2104 HMAC (SHA-1/256/512)، محلل `otpauth://totp/...`، فحص زمني ثابت لمنع هجمات القنوات الجانبية وشريط تقدم بصري للعد التنازلي في الطرفية (`svault totp add`, `svault totp code`, `svault totp list`, `svault totp verify`).
8. **حارس الحافظة منتهي الصلاحية تلقائياً (`src/clipboard_guard.rs`)** — ينسخ البيانات الحساسة بأمان إلى حافظة Windows ويمسحها تلقائياً بعد مهلة قابلة للضبط (مثل `--clip-ttl 15`). يحقن تنسيقات خصوصية Windows 10/11 لمنع التسجيل في محفوظات الحافظة (Win + V) أو المزامنة السحابية، مع مقارنة بصمة SHA-256 في زمن ثابت لمنع مسح بيانات جديدة للمستخدم.
9. **درع تصحيح الأخطاء كوشي ريد-سولومون (`src/armor.rs`)** — يضيف أشرطة تكافؤ تصحيح الأخطاء وتصدير/استيراد `.svault.asc` مدرع بنص ASCII لمقاومة تلف البتات وانقطاع الإرسال. يستخدم مصفوفة توليد كوشي $[I_K; A]$ فوق $\text{GF}(256)$ مما يضمن خصائص MDS: أي $K$ أشرطة سليمة من أصل $K+M$ كافية لإعادة بناء البيانات بالكامل (`svault repair`).
10. **حزم الدلائل وقوائم الملفات المتعددة (`src/archive.rs`)** — يحزم أشجار المجلدات مع تسوية المسارات النسبية وحماية متعددة الطبقات ضد Zip Slip وقنابل تخفيف الضغط وقوائم تجزئة SHA-256 لكل ملف وحفظ أذونات الملفات في حاوية `SVLT` مغلقة (`svault pack-dir` / `svault unpack-dir`).
11. **اشتقاق المفتاح بعاملين: ملف مفتاح + كلمة مرور (`src/keyfile.rs`)** — يدمج ملف مفتاح خارجي أو USB (`--keyfile <path>`) مع كلمة المرور عبر تدفق HMAC-SHA256 بحجم 64 KiB قبل إدخاله في Argon2id.
12. **تشفير التدفق المجزأ للملفات الضخمة (`src/stream.rs`)** — تدفق موثق بحجم 4 MiB لكل كتلة مع استهلاك ذاكرة ثابت $O(1)$ لتشفير ملفات بحجم عدة جيجابايت مع حماية مفتاح التدفق بـ Windows DPAPI وتطبيق سياسات القفل الزمني.
13. **تقرير الفروق البصرية والإحصائية للناقل المستتر (`src/diff.rs`)** — يقيم التشوه البصري (MSE, PSNR, MAE, معدل قلب LSB) والتشوه الصوتي (SNR, PSNR) وفرق إنتروبيا شانون $\Delta H$ (`svault compare <original> <stego>`).
14. **مفتاح الرجل الميت وحارس التدمير الذاتي عند استنفاد المحاولات (`src/guard.rs`)** — يرتبط بسجل تتبع محاولات منيع للتلاعب (`.guard`). عند وصول المحاولات الفاشلة إلى $K$ أو انقضاء مهلة عدم النشاط، ينفذ طحناً وتدميراً مشفراً على 3 مراحل (0x00, 0xFF, CSPRNG) ويمسح الملف نهائياً.
15. **مولد كلمات المرور الحتمي و CSPRNG (`src/passgen/`)** — توليد عبارات Diceware بـ 2,048 كلمة BIP-39، وتوليد كلمات مرور خالية من اللبس البصري (`--exclude-ambiguous`)، وبايتات عشوائية، واشتقاق حتمي من بذرة رئيسية (`svault keygen`).
16. **مخرجات JSON منظمة موحدة (`--json`)** — تدعم جميع الأوامر إرجاع مخرجات JSON قياسية متوافقة مع الأتمتة وخطوط أنابيب CI/CD.
17. **تدوير مفاتيح الحاويات (`rotate`, `src/rotate.rs`)** — يعيد تشفير الحاويات أو وسائط الإخفاء ذرّياً بأملاح ومفاتيح جديدة دون فك تشفيرها إلى القرص.
18. **قوائم نزاهة منفصلة والتحقق برمز الكناري (`canary`, `src/canary.rs`)** — ينشئ ويتحقق من قوائم فحص SHA-256 موقعة بـ HMAC-SHA256 لمراقبة سلامة المجلدات.
19. **محرك إخفاء الصوتيات MP3 ID3v2 وإطارات الصوت (`src/mp3/`)** — يخفي البيانات في ملفات MP3 عبر إطارات PRIV أو حشوات الإطارات مع إنكار معقول.
20. **ربط مفاتيح العتاد FIDO2 / Windows Hello (`src/hardware_token/`)** — يربط مفاتيح التشفير بمفاتيح FIDO2 USB المادية (YubiKey) أو المقاييس الحيوية لـ Windows Hello عبر CTAP2 PRF و Argon2id (`svault fido2`).
21. **تغليف المفاتيح الهجين المقاوم للحوسبة الكمومية (`src/pq_kem/`)** — ختم غير متماثل ثنائي الطبقة يجمع بين X25519 الكلاسيكي و NIST FIPS 203 ML-KEM-768 المقاوم للكم (`svault kem`).
22. **تصفير الذاكرة الاستباقي (`zeroize`)** — مسح مفاتيح التشفير والبصمات والمخازن المؤقتة الحساسة من الذاكرة فوراً بكتابة 0x00 عند إفلاتها.

</details>

---

## 🏛️ بنية التخزين وإخفاء البيانات

<details open>
<summary><b>🏛️ بنية التخزين وإخفاء البيانات</b></summary>
<br>

```text
  [ البيانات السرية الرئيسية ] ──▶ [ ChaCha20-Poly1305 + حشوة CSPRNG ] ──┐ (الفتحة المخفية)
                                                                           │
  [ حمولة الطُعم ]             ──▶ [ تشفير ChaCha20-Poly1305 ]          ──┴─▶ حاوية SVLT v2 (.svault)
                                                                                  ├── تخزين مباشر على القرص
                                                                                  └── ناقل إخفاء البيانات
                                                                                        ├── صورة PNG (.png)
                                                                                        ├── صوت WAV (.wav)
                                                                                        ├── صورة BMP (.bmp)
                                                                                        └── صوت MP3 (.mp3)
```

</details>

---

## ⚡ الميزات الأساسية والضمانات الأمنية

<details open>
<summary><b>⚡ الميزات الأساسية والضمانات الأمنية</b></summary>
<br>

- **Argon2id + ChaCha20-Poly1305 AEAD** — ملح عشوائي 128 بت، قيمة Nonce عشوائية 96 بت، واشتقاق مفتاح 256 بت مع وسم Poly1305 للتوثيق؛ أي تعديل يؤدي لرفض فك التشفير فوراً.
- **حارس الحافظة منتهي الصلاحية تلقائياً (`clip`)**:
  - **تكامل مباشر مع Win32**: استدعاء مباشر لوظائف حافظة Windows مع 10 محاولات ارتداد تلقائي.
  - **حظر السجل والمزامنة السحابية**: حقن بيانات التعريف (`CanIncludeInClipboardHistory`, `ExcludeClipboardContentFromMonitorProcessing`) لمنع حفظها في سجل Win+V أو سحابة مايكروسوفت.
  - **مطابقة زمنية ثابتة**: فحص SHA-256 بدون تفرع شرطي (`constant_time_eq_32`) لضمان تنظيف الحافظة فقط إذا كانت لا تزال تحتوي على القيمة المحمية.
  - **عد تنازلي بصري وتنظيف فوري**: شريط تقدم في الطرفية (`[████████░░] 12s remaining`) وزر Enter للتنظيف الفوري ونمط صامت (`--silent`).
  - **تكامل شامل مع الأوامر**: تتوفر خيارات `--clip` و `--clip-ttl <ثوان>` في `decrypt` و `extract` و `totp code`.
- **خزينة RFC 6238 TOTP 2FA (`totp`)**:
  - **صفر تبعيات خارجية**: كود Base32 كامل و SHA-1 و HMAC مع اجتياز كامل لمتجهات الاختبار الرسمية.
  - **ربط بالعتاد وتوثيق AEAD**: تخزين بيانات الحساب داخل حاويات `.svault` محمية بـ Argon2id و DPAPI.
  - **توافق كامل مع Key URI**: تحليل وتوليد صيغ `otpauth://totp/...` القياسية.
  - **حماية زمنية ضد هجمات التوقيت**: مقارنة زمنية ثابتة مع نافذة تسامح قابلة للضبط ($\pm S$).
- **مدقق قوة كلمة المرور والإنتروبيا (`audit`)**:
  - **حساب إنتروبيا شانون**: $0.0 \le H \le 8.0$ بت لكل بايت وتقدير حجم فضاء المفاتيح.
  - **كشف الأنماط الضعيفة**: رصد التكرار والتسلسلات ومسارات لوحة المفاتيح وكلمات المرور الشائعة.
  - **تقدير أزمنة الكسر**: نمذجة الهجمات عبر الإنترنت (100/ثانية)، وخارج الإنترنت بـ Argon2id ($10^3$/ثانية)، وعبر مصفوفات GPU ($10^{10}$/ثانية).
  - **تحليل ناقلات الإخفاء**: فحص مقاطع PNG وكتل WAV و LSB لبكسلات BMP واختبارات كاي-تربيع ($\chi^2$).
- **مشاركة سر شامير ($M$-of-$N$)**:
  - **حسابات حقل بزمن ثابت**: ضرب بدون تفرع وعكس فيرما ($a^{-1} = a^{254}$) فوق $\text{GF}(256)$ بدون جداول بحث.
  - **سلامة ثنائية الطبقة**: بصمة SHA-256 مدمجة وفحص CRC-32 لكل حصة لمنع التلاعب.
- **حاويات الإنكار المعقول بكلمة مرور مزدوجة**:
  - **فك تشفير تلقائي**: فتح الفتحة المناسبة بحسب كلمة المرور المدخلة تلقائياً.
  - **فتحة مخفية غير قابلة للإثبات**: لا توجد ترويسات صريحة، والبيانات اللاحقة تتطابق إحصائياً مع الضجيج العشوائي (~8.0 بت/بايت).
  - **حشوة تشتيت الحجم (`--padding <bytes>`)**: حشوة عشوائية من CSPRNG لمنع التحليل المعتمد على طول الملف.
- **ربط بالعتاد والجلسة (`--dpapi`)** — تشفير محمي بـ Windows DPAPI لقصر الاسترداد على جلسة المستخدم الأصلية.
- **تصفير استباقي للذاكرة (`zeroize`)** — مسح الذاكرة الحساسة تلقائياً عند انتهاء نطاق استخدامها.
- **إخفاء بيانات دون فقد في صور PNG (`embed` / `extract`)** — حقن مقطع `svLt` قبل `IEND` مع فحص CRC-32 ودعم خزائن الطُعم.
- **إخفاء بيانات الصوت WAV (`embed-wav` / `extract-wav`)**:
  - **نمط مقطع RIFF (`--mode chunk`)**: إضافة مقطع بيانات وصفية `svLt` مع CRC-32.
  - **نمط LSB لعينات 16 بت (`--lsb`)**: تعديل البت الأقل أهمية دون أي أثر صوتي أو تغيير في الحجم.
- **إخفاء بيانات LSB في صور BMP بدقة 24 بت (`embed-bmp` / `extract-bmp`)**:
  - **الحفاظ على حشوة الصفوف**: حماية بنية 4 بايت وتعديل قنوات R, G, B حصراً.
  - **مظروف أمني من 12 بايت**: تأطير الحمولة مع تحقق CRC-32 بزمن ثابت.
- **درع تصحيح الأخطاء كوشي ريد-سولومون (`armor` / `dearmor` / `repair`)**:
  - **ترميز MDS فوق $\text{GF}(256)$**: مصفوفة توليد $[I_K; A]$. أي $K$ أشرطة سليمة تستعيد كامل البيانات عبر حذف غاوس.
  - **ربط CRC-32 للأشرطة و SHA-256 كلي**: عزل دقيق للأضرار وتوثيق الحاوية بالكامل.
  - **إصلاح ذاتي وتلقائي (`repair` / `dearmor`)**: معالجة التلف واستعادة الملف فورياً.
- **حزم الدلائل وقوائم الملفات (`pack-dir` / `unpack-dir`)**:
  - **هيكل `SVAR` الثنائي**: ترويسة من 18 بايت، ملخصات SHA-256 فردية وختم CRC-32.
  - **منع Zip Slip وتخطي المسارات**: رفض المسارات المطلقة وتسميات أجهزة Windows المحجوزة.
  - **حماية ضد القنابل المضغوطة**: سقف أقصى 8 جيجابايت للأرشيف و 4 جيجابايت للملف الواحد.
- **تقدير سعة الناقل الشامل (`capacity`)** — حساب السعة الصافية بدقة لكل من `.bmp`, `.wav`, `.png`, `.mp3`.
- **فحص الترويسة بدون معرفة مسبقة (`inspect`)** — عرض الإصدار ووسم الطُعم والملح دون فك التشفير أو كشف الحجم المخفي.
- **سياسات القفل الزمني وانتهاء الصلاحية (`policy`)**:
  - **ترويسة سياسة مصادق عليها (`SVPO`)**: ترويسة من 28 بايت مع الطوابع الزمنية والشرح والتحقق بـ CRC-32.
  - **ربط البيانات المصاحبة (AAD)**: حقن السياسة كبيانات موثقة إضافية في ChaCha20-Poly1305.
- **ملف المفتاح المادي + كلمة المرور (`keyfile`)** — معالجة تدفق 64 KiB بحجم ذاكرة ثابت واشتقاق بذرة 256 بت لـ Argon2id.
- **تشفير التدفق المجزأ (`stream`)** — تدفق بذاكرة ثابتة $O(1)$ للملفات الضخمة متعددة الجيجابايت.
- **تقرير الفروق والمقارنة (`compare`)** — تقييم الفروق البصرية والصوتية والإحصائية $\Delta H$.
- **حارس التدمير الذاتي ومفتاح الرجل الميت (`guard`)** — تدمير الملف بـ 3 مراحل عند استنفاد المحاولات أو انتهاء المهلة.
- **مولد كلمات المرور الحتمي (`keygen`)** — عبارات Diceware BIP-39 وبايتات عشوائية وبذور مشتقة.
- **محيط سطر أوامر تفاعلي في الذاكرة (`repl`)** — إدارة الخزائن في الذاكرة مع حماية الحافظة.
- **طحن وإتلاف الملفات الآمن (`shred`)** — كتابة `0x00` ثم `0xFF` ثم بيانات عشوائية قبل الحذف.
- **ملف ثنائي ثابت ومستقل** — بدون أي متطلبات تشغيل خارجية.

</details>

---

## 🚀 البدء السريع ومسارات عمل واجهة السطر الأوامر (CLI)

<details open>
<summary><b>🚀 البدء السريع ومسارات عمل واجهة السطر الأوامر (انقر على الفئة للطي / التوسيع)</b></summary>
<br>

<details open>
<summary><b>🔐 1. التشفير ثنائي الطبقة وخزائن الطُعم ذات الإنكار المعقول (#1 - #6)</b></summary>
<br>

```bash
# 1. تشفير ملف بكلمة مرور وربط عتادي بواسطة Windows DPAPI
svault encrypt -i wallet-seed.txt -o wallet.svault -p "your-strong-passphrase" --dpapi

# 2. تشفير خزينة إنكار معقول تحتوي على السر الحقيقي وبيانات الطُعم معاً
svault encrypt -i classified.txt --decoy shopping-list.txt -o deniable.svault \
  -p "primary-secret-pass" --decoy-passphrase "decoy-harmless-pass" --padding 512

# 3. فك تشفير حاوية الإنكار (إدخال كلمة مرور الطُعم يعرض فقط البيانات غير الضارة)
svault decrypt -i deniable.svault -o revealed.txt -p "decoy-harmless-pass"
# إدخال كلمة المرور الرئيسية يسترجع السر الحقيقي الكامل
svault decrypt -i deniable.svault -o restored.txt -p "primary-secret-pass"

# 4. فحص البيانات الوصفية للخزينة دون فك التشفير (.svault, .png, .wav أو .bmp)
svault inspect deniable.svault

# 5. إخفاء خزينة طُعم ثنائية كلمة المرور مباشرة وبدون فقدان داخل صورة PNG
svault embed -c wallpaper.png -s classified.txt --decoy shopping-list.txt -o wallpaper-stego.png \
  -p "primary-secret-pass" --decoy-passphrase "decoy-harmless-pass"

# 6. استخراج السر من صورة PNG (باستخدام كلمة المرور الرئيسية أو كلمة مرور الطُعم)
svault extract -c wallpaper-stego.png -o restored-seed.txt -p "primary-secret-pass"
svault extract -c wallpaper-stego.png -o decoy-seed.txt --decoy-passphrase "decoy-harmless-pass"
```

</details>

<details open>
<summary><b>🖼️ 2. إخفاء البيانات بدون فقد في الوسائط: PNG و WAV و BMP و MP3 وتقدير السعة (#7 - #13)</b></summary>
<br>

```bash
# 7. إخفاء سر داخل ملف صوتي WAV (مقطع فرعي RIFF أو LSB لعينات 16 بت)
svault embed-wav -c track.wav -s classified.txt -o track-lsb.wav -p "primary-secret-pass" --lsb

# 8. استخراج وفك تشفير السر من ملف صوتي WAV (كشف تلقائي)
svault extract-wav -c track-lsb.wav -o restored-audio.txt -p "primary-secret-pass"

# 9. تقدير السعة المتاحة لإخفاء البيانات في الناقل (.bmp, .wav, .png أو .mp3)
svault capacity landscape.bmp
svault capacity track.wav --json
svault capacity song.mp3

# 10. إخفاء سر داخل صورة BMP بدقة 24 بت عبر تعديل LSB للبكسلات
svault embed-bmp -c landscape.bmp -s classified.txt -o landscape-stego.bmp -p "primary-secret-pass"

# 11. استخراج السر من صورة BMP مباشرة إلى الحافظة ذاتية الإخلاء (15 ثانية)
svault extract-bmp -c landscape-stego.bmp -p "primary-secret-pass" --clip --clip-ttl 15

# 12. إخفاء سر داخل ملف صوتي MP3 (إطار ID3v2 PRIV أو حشوة بين الإطارات)
svault embed-mp3 -c song.mp3 -s classified.txt -o song-stego.mp3 -p "primary-secret-pass" --mode id3v2
svault embed-mp3 -c song.mp3 -s classified.txt -o song-frame.mp3 -p "primary-secret-pass" --mode frame

# 13. استخراج السر من ملف صوتي MP3 (كشف تلقائي لنمط الإخفاء)
svault extract-mp3 -c song-stego.mp3 -o restored-mp3.txt -p "primary-secret-pass"
```

</details>

<details open>
<summary><b>🧩 3. الإتلاف الآمن ومشاركة سر شامير وتدقيق الإنتروبيا (#12 - #16)</b></summary>
<br>

```bash
# 12. إتلاف وطحن الملف النصي الأصلي بأمان (3 مراحل للكتابة فوقه)
svault shred classified.txt --passes 3

# 13. تقسيم مفتاح استرداد رئيسي إلى 3-من-5 حصص شامير
svault split -s "your-master-seed-or-secret" -m 3 -n 5 -o shares/share

# 14. دمج أي 3 حصص لإعادة بناء السر الأصلي بالكامل
svault combine shares/share_1.share shares/share_3.share shares/share_5.share -o restored.txt

# 15. تدقيق قوة كلمة المرور وإنتروبيا شانون وتقدير زمن كسرها
svault audit -p "Correct-Horse-Battery-Staple-2026!"

# 16. تدقيق صورة أو حاوية إخفاء بيانات لرصد التناقضات والحمولات الخفية
svault audit wallpaper-stego.png --json
```

</details>

<details open>
<summary><b>⏱️ 4. مستودع RFC 6238 TOTP 2FA وحارس الحافظة ذاتي الإخلاء (#17 - #23)</b></summary>
<br>

```bash
# 17. إضافة اعتمادية TOTP 2FA عبر مفتاح Base32 أو رابط otpauth://
svault totp add github --secret "JBSWY3DPEHPK3PXP" --issuer "GitHub" --vault totp.svault -p "vault-pass"
svault totp add --uri "otpauth://totp/Google:alice?secret=JBSWY3DPEHPK3PXP&issuer=Google" --vault totp.svault -p "vault-pass"

# 18. توليد رمز OTP 2FA المباشر مع شريط تقدم للعد التنازلي (أو --json)
svault totp code github --vault totp.svault -p "vault-pass"
svault totp code github --vault totp.svault -p "vault-pass" --json

# 19. التحقق من صحة رمز OTP وفق نافذة التسامح الزمني (+/- خطوة واحدة)
svault totp verify github 123456 --skew 1 --vault totp.svault -p "vault-pass"

# 20. عرض وتصدير قائمة حسابات 2FA
svault totp list --vault totp.svault -p "vault-pass"
svault totp export github --vault totp.svault -p "vault-pass"

# 21. نسخ سر إلى الحافظة مع حمايته بمسح تلقائي بعد 15 ثانية (أو بنمط صامت)
svault clip copy "my-super-secret-password" --ttl 15
svault clip copy "my-super-secret-password" --ttl 15 --silent

# 22. فحص حالة الحافظة وبيانات حظر السجل أو تنظيفها يدوياً
svault clip status
svault clip clear

# 23. فك التشفير مباشرة إلى الحافظة المحمية دون طباعة في الطرفية أو حفظ بالقرص
svault decrypt -i secret.svault -p "vault-pass" --clip --clip-ttl 30
svault totp code github --vault totp.svault -p "vault-pass" --clip --clip-ttl 15
```

</details>

<details open>
<summary><b>🛡️ 5. درع كوشي ريد-سولومون وتجميع الدلائل (#24 - #30)</b></summary>
<br>

```bash
# 24. تدريع حاوية .svault بشرائط تكافؤ كوشي ريد-سولومون بتنسيق ASCII (.svault.asc)
svault armor -i secret.svault -o secret.svault.asc -k 4 -m 2

# 25. فك تدريع الملف النصي وتحويله إلى حاوية .svault الثنائية الأصلية
svault dearmor -i secret.svault.asc -o recovered.svault

# 26. إصلاح ملف .svault.asc تالف ذاتياً باستخدام أشرطة التكافؤ
svault repair -i corrupted.svault.asc -o repaired.svault.asc --json
svault repair -i corrupted.svault.asc -o direct_recovered.svault --binary

# 27. فحص وتدقيق أشرطة الحاوية المدرعة وسلامتها
svault inspect secret.svault.asc
svault audit secret.svault.asc --json

# 28. حزم شجرة دليل بالكامل داخل حاوية .svault مشفرة ومختومة
svault pack-dir -i ./my_project -o project.svault -p "pack-passphrase" --list

# 29. حزم الدليل مباشرة داخل ناقل إخفاء (PNG, WAV, BMP, MP3) أو درع ASCII
svault pack-dir -i ./my_project -o project.png -p "pack-passphrase" --carrier cover.png
svault pack-dir -i ./my_project -o project.svault.asc -p "pack-passphrase" --armor

# 30. فك حزم الدليل أو استعراض القائمة أو التحقق المسبق من البصمات
svault unpack-dir -i project.svault -p "pack-passphrase" --list
svault unpack-dir -i project.svault -p "pack-passphrase" --verify-only
svault unpack-dir -i project.svault -o ./restored_project -p "pack-passphrase" --overwrite
```

</details>

<details open>
<summary><b>⏳ 6. سياسات القفل الزمني وملفات USB والتدفق المجزأ (#31 - #42)</b></summary>
<br>

```bash
# 31. تشفير مع سياسة قفل زمني لحفظ الأمانة (لا يفتح قبل تاريخ مستقبلي)
svault encrypt -i escrow.txt -o escrow.svault -p "vault-pass" --not-before "2026-12-31T00:00:00Z" --policy-desc "Year-End Escrow"

# 32. تشفير مع سياسة انتهاء الصلاحية التلقائي (تنتهي بعد ساعتين أو بتاريخ محدد)
svault encrypt -i token.txt -o token.svault -p "vault-pass" --expires-in 2h --policy-desc "Session Token"
svault encrypt -i doc.txt -o doc.svault -p "vault-pass" --expires-at "2026-10-15"

# 33. فحص البيانات الوصفية للسياسة دون فك التشفير
svault inspect escrow.svault
svault inspect escrow.svault --json

# 34. اختبار فك التشفير مقابل طابع زمني مرجعي محدد
svault decrypt -i escrow.svault -o restored.txt -p "vault-pass" --at-time "2027-01-01"

# 35. توليد ملف مفتاح USB عشوائي عالي الأمان (CSPRNG, افتراضياً 64 بايت)
svault keyfile generate -o usb_token.key --bytes 64

# 36. فحص بصمة ملف المفتاح وإنتروبيا شانون (نصياً و JSON)
svault keyfile inspect usb_token.key
svault keyfile inspect usb_token.key --json
svault keyfile fingerprint usb_token.key

# 37. تشفير وفك تشفير بمصادقة ثنائية 2FA (كلمة مرور + ملف مفتاح)
svault encrypt -i secret.txt -o sealed.svault -p "master-pass" -k usb_token.key
svault decrypt -i sealed.svault -o restored.txt -p "master-pass" -k usb_token.key

# 38. تشفير معتمد على ملف المفتاح حصراً دون كلمة مرور
svault encrypt -i token.txt -o hardware.svault -k usb_token.key
svault decrypt -i hardware.svault -o restored.txt -k usb_token.key

# 39. حزم دليل داخل خزينة مشفرة مع 2FA لملف المفتاح
svault pack-dir -i ./confidential -o archive.svault -p "pack-pass" -k usb_token.key
svault unpack-dir -i archive.svault -o ./unpacked -p "pack-pass" -k usb_token.key

# 40. تشفير ملفات ضخمة متعددة الجيجابايت بتدفق مجزأ (كتل 4 MiB افتراضياً)
svault stream encrypt -i large_dataset.iso -o large_dataset.svault -p "stream-pass"
svault encrypt -i database.backup -o db.svault -p "stream-pass" --stream --chunk-size 8M

# 41. فك تشفير حاوية التدفق (يتعرف تلقائياً على تنسيق SVST)
svault decrypt -i large_dataset.svault -o restored.iso -p "stream-pass"
svault stream decrypt -i db.svault -o restored_db.backup -p "stream-pass"

# 42. فحص بيانات الحاوية المتدفقة دون فك التشفير
svault stream inspect large_dataset.svault
svault stream inspect large_dataset.svault --json
```

</details>

<details open>
<summary><b>🚨 7. تقارير الفروق وحارس التدمير الذاتي وتوليد كلمات المرور (#43 - #53)</b></summary>
<br>

```bash
# 43. مقارنة الناقل الأصلي بناقل إخفاء البيانات (PNG, BMP, WAV أو ملف ثنائي)
svault compare cover.bmp stego.bmp
svault compare cover.png stego.png --json
svault diff original.wav stego.wav --detailed

# 44. تسليح الخزينة بحارس تدمير ذاتي لـ 3 محاولات فاشلة ومفتاح رجل ميت
svault encrypt -i secret.txt -o guarded.svault -p "vault-pass" --max-attempts 3 --dead-man 7d --guard-companion

# 45. تسليح ملف أو حاوية إخفاء بيانات موجودة مباشرة
svault guard arm -t stego.png --max-attempts 3 --companion
svault guard arm -t vault.svault --max-attempts 5 --dead-man 24h

# 46. فحص حالة الحارس وعدد المحاولات المتبقية (نصياً و JSON)
svault guard status -t guarded.svault
svault guard status -t guarded.svault --json

# 47. تسجيل الحضور لتجديد مهلة مفتاح الرجل الميت أو إعادة ضبط العداد
svault guard checkin -t guarded.svault --interval 30d
svault guard reset -t guarded.svault

# 48. تعطيل الحارس أو تفعيل الإتلاف العاجل للملف فوراً
svault guard disarm -t guarded.svault
svault guard trigger -t guarded.svault --force --passes 3

# 49. توليد عبارة استرداد Diceware BIP-39 مكونة من 6 كلمات
svault keygen --words 6

# 50. توليد عبارة Diceware مخصصة بأرقام وأحرف كبيرة
svault keygen --words 4 --separator "." --capitalize --number

# 51. توليد كلمة مرور بـ 24 حرفاً مع تصفية الالتباس وفحص الإنتروبيا
svault keygen --length 24 --exclude-ambiguous --entropy

# 52. اشتقاق كلمة مرور حتمياً من بذرة رئيسية وسياق خدمة
svault keygen --words 6 --seed "master-recovery-seed" --context "github-token"

# 53. توليد رمز عشوائي مشفر بحجم 32 بايت ونسخه للحافظة
svault keygen --bytes 32 --base64 --clip --clip-ttl 30
svault keygen --bytes 20 --base32 --json
```

</details>

<details open>
<summary><b>💻 8. تدوير المفاتيح ونزاهة الكناري ومحيط REPL التفاعلي (#54 - #63)</b></summary>
<br>

```bash
# 54. تدوير مفاتيح الحاوية بكلمة مرور جديدة وملح وقيمة Nonce طازجة
svault rotate -i vault.svault -o rotated.svault -p "old-secret" -n "new-secret"

# 55. تدوير واستبدال الحاوية في مكانها ذرياً
svault rotate -i vault.svault --in-place -p "old-secret" -n "new-secret"
svault rotate -i stego.bmp --in-place -p "old-pass" -n "new-pass"

# 56. تدوير بيانات اعتماد وسائط الإخفاء (PNG, WAV, BMP أو درع ASCII)
svault rotate -i carrier.png -o rotated.png -p "old-pass" -n "new-pass"
svault rotate -i carrier.asc -o rotated.asc -p "old-pass" -n "new-pass"

# 57. تدوير المفاتيح مع تبديل ربط DPAPI بالعتاد أو مسح السياسات
svault rotate -i vault.svault -o dpapi_vault.svault -p "old-pass" -n "new-pass" --dpapi
svault rotate -i locked.svault -o unlocked.svault -p "old-pass" -n "new-pass" --clear-policy --json

# 58. تهيئة قائمة فحص الكناري للتحقق من نزاهة الدليل المستهدف
svault canary init -d ./vaults
svault canary init -d ./vaults -p "canary-auth-secret" --json

# 59. التحقق من صحة ملفات الدليل ضد التلاعب عبر قائمة الكناري
svault canary verify -d ./vaults
svault canary verify -d ./vaults -p "canary-auth-secret" --strict --json

# 60. تشغيل محيط REPL تفاعلي في الذاكرة لإدارة الخزينة
svault repl -v myvault.svault -p "session-pass"

# 61. تنفيذ أوامر REPL مجمعة بدون واجهة تفاعلية عبر --exec
svault repl -v myvault.svault -p "session-pass" --exec "set api_key sk_live_xyz --tag prod; set db_pass secret; save"

# 62. الاستعلام عن سر مباشرة مع حمايته بحافظة ذاتية الإخلاء
svault repl -v myvault.svault -p "session-pass" --exec "get api_key --clip --clip-ttl 15"

# 63. تشغيل REPL بنمط القراءة فقط أو تصدير المدخلات بصيغة JSON
svault repl -v myvault.svault -p "session-pass" --readonly --exec "list" --json
svault repl -v myvault.svault -p "session-pass" --exec "export ./backup.json; exit"
```

</details>

<details open>
<summary><b>🔑 9. ربط أوراق اعتماد مفاتيح العتاد FIDO2 / Windows Hello (#64 - #70)</b></summary>
<br>

```bash
# 64. فحص قدرات رموز العتاد في النظام المضيف (Windows Hello, WebAuthn API, USB HID)
svault fido2 status
svault fido2 status --json

# 65. تسجيل مفتاح FIDO2 USB أو اعتمادية Windows Hello
svault fido2 enroll yubikey-5c --type usb --user alice --output ./yubikey.json
svault fido2 enroll hello-tpm --type hello --pin 849201 --json

# 66. اختبار توكيد المصادق والتحقق من بصمة اشتقاق PRF
svault fido2 test ./yubikey.json
svault fido2 test ./yubikey.json --json

# 67. تشفير الحاوية بربط اعتمادية FIDO2 بالعتاد مع كلمة المرور
svault encrypt -i secret.txt -o sealed.svault --fido2-cred ./yubikey.json -p "master-pass"

# 68. فك تشفير الحاوية باستخدام اعتمادية العتاد المسجلة
svault decrypt -i sealed.svault -o restored.txt --fido2-cred ./yubikey.json -p "master-pass"

# 69. مصادقة متعددة العوامل 2FA: ملف مفتاح + رمز FIDO2 المادي (بدون كلمة مرور)
svault encrypt -i secret.txt -o mfa.svault -k usb_token.key --fido2-cred ./yubikey.json
svault decrypt -i mfa.svault -o restored.txt -k usb_token.key --fido2-cred ./yubikey.json

# 70. تدوير الحاوية الحالية لإضافة أو إزالة ربط عتاد FIDO2
svault rotate -i sealed.svault --in-place -p "old-pass" -n "new-pass" --fido2 --fido2-cred ./yubikey.json
svault rotate -i sealed.svault --in-place -p "new-pass" -n "plain-pass" --no-fido2 --fido2-cred ./yubikey.json
```

</details>

<details open>
<summary><b>⚛️ 10. تغليف المفاتيح الهجين المقاوم للحوسبة الكمومية (X25519 + ML-KEM-768) (#71 - #74)</b></summary>
<br>

```bash
# 71. توليد زوج مفاتيح هجين مقاوم للحوسبة الكمومية (X25519 + ML-KEM-768)
svault kem keygen -p recipient.pub -s recipient.key
svault kem keygen -p recipient.pub -s recipient.key --json

# 72. ختم ملف سري لمفتاح المستلم العام (ثنائي أو مدرع بنص ASCII)
svault kem seal -i classified.txt -o sealed.svault.pq -k recipient.pub
svault kem seal -i classified.txt -o sealed.asc -k recipient.pub --armor --json

# 73. فحص البيانات الوصفية لحاوية ما بعد الكم (المفتاح المؤقت، حجم الشفرة، CRC-32)
svault kem inspect -i sealed.svault.pq
svault kem inspect -i sealed.asc --json

# 74. فتح وفك تشفير الخزينة المقاومة للحوسبة الكمومية بمفتاح المستلم الخاص
svault kem open -i sealed.svault.pq -o restored.txt -k recipient.key
svault kem open -i sealed.asc -o restored.txt -k recipient.key --json
```

</details>

</details>

---

## 🔒 أمان الذاكرة وثوابت الحماية

<details open>
<summary><b>🔒 أمان الذاكرة وثوابت الحماية</b></summary>
<br>

- **لغة Rust آمنة بنسبة 100% وتشفير بزمن ثابت**: لا توجد أي كتل `unsafe` في مسارات معالجة البيانات المشفرة؛ حسابات حقول جالوا خالية من التفرع لحظر هجمات القنوات الجانبية المعتمدة على التوقيت.
- **تصفير استباقي ومحصن للذاكرة**: تطبق جداول المفاتيح والبيانات الصريحة تصفير الذاكرة مع حواجز المترجم عند التحرير عبر `zeroize`.
- **ربط ملف تعريف العتاد**: يضمن تغليف Windows DPAPI الاختياري عدم إمكانية فك تشفير النص خارج الجهاز وجلسة المستخدم الأصلية.
- **دفاعات ضد تجاوز المسارات وقنابل الضغط**: مسارات نسبية معيارية، وفحوصات صارمة لمنع هجمات استنزاف الموارد.

</details>

---

## 📄 الترخيص وحقوق التأليف

<details open>
<summary><b>📄 الترخيص وحقوق التأليف</b></summary>
<br>

حقوق النشر 2026 **GHSFS** ([https://github.com/GHSFS](https://github.com/GHSFS)).

مرخص بموجب **Apache License, Version 2.0** ([`LICENSE`](../../LICENSE)).
وفقاً للقسم 4(d) من رخصة Apache 2.0، يجب أن تحتفظ أي نسخة معاد توزيعها أو أعمال مشتقة بإشعارات العزو الواردة في ملف [`NOTICE`](../../NOTICE).

</details>
