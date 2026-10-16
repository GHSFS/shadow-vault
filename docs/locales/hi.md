<div align="center">

<p align="center">
  <a href="../../README.md">🇺🇸 English</a> · <a href="./ko.md">🇰🇷 한국어</a> · <a href="./zh-CN.md">🇨🇳 中文</a> · <a href="./es.md">🇪🇸 Español</a> · <strong>🇮🇳 हिन्दी</strong><br />
  <a href="./ar.md">🇸🇦 العربية</a> · <a href="./pt-BR.md">🇧🇷 Português</a> · <a href="./ru.md">🇷🇺 Русский</a> · <a href="./fr.md">🇫🇷 Français</a> · <a href="./id.md">🇮🇩 Bahasa Indonesia</a>
</p>

# shadow-vault (`svault`)

> ज़ीरो-ट्रस्ट स्टेग्नोग्राफी और दोहरी-परत हार्डवेयर-बाध्य एन्क्रिप्टेड वॉल्ट — संवेदनशील फ़ाइलों को सामान्य PNG/ऑडियो वाहकों में छुपाएं, Argon2id + ChaCha20-Poly1305 + Windows DPAPI से सील करें, या दोहरे-पासवर्ड वाले प्रशंसनीय इनकार (Plausible Deniability) डिकॉय वॉल्ट बनाएं।

[![Build](https://github.com/GHSFS/shadow-vault/actions/workflows/build.yml/badge.svg)](https://github.com/GHSFS/shadow-vault/actions/workflows/build.yml)
[![Tests](https://github.com/GHSFS/shadow-vault/actions/workflows/test.yml/badge.svg)](https://github.com/GHSFS/shadow-vault/actions/workflows/test.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](../../LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20x64-0078D6)](#-त्वरित-शुरुआत-और-cli-कार्यप्रवाह)

</div>

---

## 🛡️ अवलोकन और मुख्य क्षमताएं

<details open>
<summary><b>🛡️ अवलोकन और मुख्य क्षमताएं</b></summary>
<br>

`shadow-vault` (`svault.exe`) Rust में लिखा गया शून्य-निर्भरता, एकल-बाइनरी क्रिप्टोग्राफ़िक वॉल्ट और स्टेग्नोग्राफी टूलकिट है, जिसे उच्च-मूल्य वाली फ़ाइलों (सीड वाक्यांश, निजी कुंजियाँ, क्रेडेंशियल्स, शोध नोट्स) के लिए सैन्य-ग्रेड सुरक्षा प्रदान करने के लिए डिज़ाइन किया गया है:

1. **दोहरी-परत प्रमाणीकृत एन्क्रिप्शन (`SVLT` v1/v2)** — मेमोरी-कठिन **Argon2id** की व्युत्पत्ति + **ChaCha20-Poly1305** AEAD को वैकल्पिक **Windows DPAPI (`CryptProtectData`)** हार्डवेयर/उपयोगकर्ता सत्र बाइंडिंग के साथ जोड़ता है। भले ही कोई हमलावर `.svault` फ़ाइल और पासवर्ड दोनों चुरा ले, फिर भी आपके मूल Windows उपयोगकर्ता सत्र के बिना इसे डिक्रिप्ट नहीं किया जा सकता।
2. **प्रशंसनीय इनकार और डिकॉय वॉल्ट (`src/decoy.rs`)** — एक ही कंटेनर में प्राथमिक गुप्त डेटा (मास्टर पासवर्ड से अनलॉक) और हानिरहित डिकॉय पेलोड (डिकॉय पासवर्ड से अनलॉक) दोनों को छुपाता है। दबाव में डिकॉय पासवर्ड देने पर केवल डिकॉय डेटा ही सामने आता है, जबकि छुपा हुआ मुख्य स्लॉट सांख्यिकीय रूप से यादृच्छिक शोर (CSPRNG पैडिंग और ChaCha20 सिफरटेक्स्ट) से पूरी तरह अप्रभेद्य रहता है।
3. **दोषरहित मीडिया स्टेग्नोग्राफी** — एन्क्रिप्टेड कंटेनरों को सामान्य मीडिया फ़ाइलों के भीतर छुपाता है:
   - **PNG छवियां (`embed` / `extract`)**: वैध IEEE 802.3 CRC-32 चेकसम के साथ `IEND` से पहले `svLt` निजी सहायक हिस्सा इंजेक्ट करता है (सीधे डिकॉय वॉल्ट छिपाने का समर्थन करता है)।
   - **WAV ऑडियो फ़ाइलें (`embed-wav` / `extract-wav`)**: CRC-32 सत्यापन के साथ RIFF/WAVE सब-चंक्स (`--mode chunk`) और 16-बिट PCM ऑडियो नमूना न्यूनतम महत्वपूर्ण बिट (LSB) प्रतिस्थापन (`--lsb`) दोनों का समर्थन करता है।
   - **BMP छवियां (`src/bmp.rs`)**: सख्त 4-बाइट पंक्ति पैडिंग संरक्षण और 12-बाइट छेड़छाड़-रोधी लिफाफे (`svLt`, लंबाई, पेलोड, CRC-32) के साथ 24-बिट असम्पीडित RGB पिक्सेल LSB छिपाव।
   - **MP3 ऑडियो फ़ाइलें (`src/mp3/`)**: ID3v2.3/ID3v2.4 निजी (`PRIV`) टैग फ़्रेम या MPEG ऑडियो लेयर III इंटर-फ़्रेम पैडिंग में पेलोड छुपाता है, जिसमें फ़्रेम सिंक सत्यापन, मेटाडेटा संरक्षण (TIT2, TPE1) और क्षमता अनुमान शामिल है।
4. **सार्वभौमिक वाहक क्षमता अनुमान (`capacity`)** — `.bmp`, `.wav`, `.png`, और `.mp3` वाहकों में कुल आकार, वास्तविक प्रयोग योग्य बाइट क्षमता और ओवरहेड का सटीक मूल्यांकन करता है (`svault capacity <carrier> [--json]`)।
5. **शमीर गुप्त साझाकरण (`M-of-N` की-विभाजन, `src/shamir.rs`)** — $\text{GF}(256)$ पर निरंतर-समय शाखाहीन परिमित क्षेत्र अंकगणित। मास्टर पुनर्प्राप्ति कुंजियों, पासवर्ड या कंटेनरों को $N$ शेयरों में विभाजित करें, जिसमें से किन्हीं $M$ शेयरों की आवश्यकता होती है (`svault split` / `svault combine`)। आर्मर्ड टेक्स्ट, कॉम्पैक्ट एकल-पंक्ति स्ट्रिंग, JSON और SHA-256/CRC-32 सत्यापन का समर्थन करता है।
6. **पासवर्ड शक्ति और वाहक एन्ट्रापी लेखा परीक्षक (`src/audit.rs`)** — शैनन एन्ट्रापी (बिट्स/बाइट), वर्ण विविधता और कमजोर पैटर्न (दोहराए गए वर्ण, कीबोर्ड वॉक, लीटस्पीक) का परीक्षण करता है। PNG, WAV, 24-बिट BMP पिक्सेल और `.svault` कंटेनरों में असामान्यताओं और छेड़छाड़ की जांच करता है (`svault audit <target>` / `svault audit -p <passphrase>`)।
7. **RFC 6238 TOTP 2FA वॉल्ट (`src/totp.rs`)** — शून्य-निर्भरता स्थानीय एन्क्रिप्टेड 2FA वॉल्ट। बेस32 (RFC 4648), RFC 3174 SHA-1, RFC 2104 HMAC (SHA-1/256/512), `otpauth://totp/...` URI पार्सर, निरंतर-समय साइड-चैनल सुरक्षा और टर्मिनल विजुअल उल्टी गिनती प्रगति बार (`svault totp add`, `svault totp code`, `svault totp list`, `svault totp verify`)।
8. **स्वचालित-समाप्ति क्लिपबोर्ड गार्ड (`src/clipboard_guard.rs`)** — क्रेडेंशियल्स को सुरक्षित रूप से Windows क्लिपबोर्ड पर कॉपी करता है और कॉन्फ़िगर करने योग्य TTL (उदा. `--clip-ttl 15`) के बाद मिटा देता है। क्लिपबोर्ड इतिहास (Win + V) और क्लाउड सिंक को रोकने के लिए मेटाडेटा इंजेक्ट करता है, और उपयोगकर्ता के बाद के डेटा को सुरक्षित रखने के लिए SHA-256 निरंतर-समय मिलान करता है।
9. **कॉची रीड-सोलोमन / त्रुटि सुधार आर्मर (`src/armor.rs`)** — पैरिटी स्ट्रिप्स और ASCII-आर्मर्ड `.svault.asc` निर्यात/आयात/मरम्मत का समर्थन करता है। $\text{GF}(256)$ पर कॉची जनरेटर मैट्रिक्स $[I_K; A]$ का उपयोग करता है जिससे $K+M$ में से कोई भी $K$ बरकरार स्ट्रिप्स पूरे डेटा का पुनर्निर्माण कर सकती हैं (`svault repair`)।
10. **निर्देशिका और बहु-फ़ाइल मैनिफ़ेस्ट पैकिंग (`src/archive.rs`)** — सापेक्ष पथ मानकीकरण, ज़िप स्लिप (Zip Slip) रोकथाम, संपीड़न बम रक्षा, प्रति-फ़ाइल SHA-256 मैनिफ़ेस्ट और अनुमतियों के संरक्षण के साथ पूर्ण निर्देशिका ट्री को एक `SVLT` कंटेनर में सील करता है (`svault pack-dir` / `svault unpack-dir`)।
11. **की-फ़ाइल + पासवर्ड दोहरी प्रमाणीकरण व्युत्पत्ति (`src/keyfile.rs`)** — बाहरी हार्डवेयर या USB की-फ़ाइल (`--keyfile <path>`) को 64 KiB स्ट्रीमिंग HMAC-SHA256 प्री-हैशिंग के माध्यम से Argon2id के साथ जोड़ता है।
12. **खंडित स्ट्रीमिंग एन्क्रिप्शन (`src/stream.rs`)** — मल्टी-गीगाबाइट बड़ी फ़ाइलों के लिए निरंतर $O(1)$ मेमोरी पर 4 MiB प्रमाणित चंक स्ट्रीमिंग (`SVST` v1 कंटेनर), Windows DPAPI कुंजी सुरक्षा और समय नीतियों के साथ।
13. **स्टेगो वाहक दृश्य और सांख्यिकीय अंतर रिपोर्ट (`src/diff.rs`)** — दृश्य संकेत विरूपण (MSE, PSNR, MAE, LSB दर), ऑडियो विरूपण (SNR, PSNR) और शैनन एन्ट्रापी अंतर $\Delta H$ का मूल्यांकन करता है (`svault compare <original> <stego>`)।
14. **डेड-मैन स्विच और अधिकतम विफलता पर स्व-विनाश गार्ड (`src/guard.rs`)** — छेड़छाड़-रोधी बहीखाता से बंधा है। $K$ बार गलत पासवर्ड दर्ज करने पर 3-चरणीय (0x00, 0xFF, CSPRNG) फ़ाइल श्रेडिंग निष्पादित करता है, और समय सीमा समाप्त होने पर स्व-विनाश करता है।
15. **निर्धारक और CSPRNG पासवर्ड जनरेटर (`src/passgen/`)** — BIP-39 2,048-शब्द डाइसवेयर, दृश्य अस्पष्टता रहित वर्ण (`--exclude-ambiguous`), यादृच्छिक बाइट्स, और मास्टर सीड व्युत्पत्ति (`svault keygen`)।
16. **एकीकृत संरचित JSON आउटपुट (`--json`)** — सभी आदेश स्वचालित स्क्रिप्ट और CI/CD पाइपलाइनों के लिए मशीन-पठनीय JSON प्रदान करते हैं।
17. **कंटेनर कुंजी रोटेशन (`rotate`, `src/rotate.rs`)** — नए साल्ट, नॉनस और क्रेडेंशियल्स के साथ बिना डिस्क पर अनपैक किए कंटेनरों को सुरक्षित रूप से पुनः एन्क्रिप्ट करता है।
18. **अलग अखंडता मैनिफ़ेस्ट और कैनरी सत्यापन (`canary`, `src/canary.rs`)** — निर्देशिका ट्री की निगरानी के लिए HMAC-SHA256 हस्ताक्षरित कैनरी उत्पन्न और सत्यापित करता है।
19. **MP3 ID3v2 और ऑडियो फ्रेम स्टेग्नोग्राफी (`src/mp3/`)** — MP3 फ़ाइलों में ID3v2 PRIV फ़्रेम या फ्रेम पैडिंग में डेटा छुपाता है।
20. **FIDO2 / Windows Hello हार्डवेयर कुंजी क्रेडेंशियल बाइंडिंग (`src/hardware_token/`)** — USB सुरक्षा कुंजियों (YubiKey) या बायोमेट्रिक्स को CTAP2 PRF और Argon2id के साथ जोड़ता है (`svault fido2`)।
21. **पोस्ट-क्वांटम हाइब्रिड कुंजी इनकैप्सुलेशन (`src/pq_kem/`)** — क्वांटम-प्रतिरोधी X25519 + NIST FIPS 203 ML-KEM-768 असममित वॉल्ट सीलिंग (`svault kem`)।
22. **मेमोरी शून्यीकरण संरक्षण (`zeroize`)** — ड्रॉप होने पर संवेदनशील कुंजी शेड्यूल्स और प्लेनटेक्स्ट बफ़र्स को मेमोरी से पूरी तरह 0x00 से मिटा दिया जाता है।

</details>

---

## 🏛️ वॉल्ट और स्टेग्नोग्राफी आर्किटेक्चर

<details open>
<summary><b>🏛️ वॉल्ट और स्टेग्नोग्राफी आर्किटेक्चर</b></summary>
<br>

```text
  [ प्राथमिक गुप्त डेटा ] ──▶ [ ChaCha20-Poly1305 + CSPRNG पैडिंग ] ──┐ (छुपा हुआ स्लॉट)
                                                                       │
  [ डिकॉय पेलोड ]        ──▶ [ ChaCha20-Poly1305 एन्क्रिप्टेड ]     ──┴─▶ SVLT v2 कंटेनर (.svault)
                                                                            ├── सीधी डिस्क संग्रहण
                                                                            └── स्टेगो वाहक
                                                                                  ├── PNG छवि (.png)
                                                                                  ├── WAV ऑडियो (.wav)
                                                                                  ├── BMP छवि (.bmp)
                                                                                  └── MP3 ऑडियो (.mp3)
```

</details>

---

## ⚡ मुख्य विशेषताएं और सुरक्षा गारंटी

<details open>
<summary><b>⚡ मुख्य विशेषताएं और सुरक्षा गारंटी</b></summary>
<br>

- **Argon2id + ChaCha20-Poly1305 AEAD** — 128-बिट रैंडम सॉल्ट, 96-बिट रैंडम नॉनस, डोमेन-पृथक 256-बिट की व्युत्पत्ति और 128-बिट Poly1305 प्रमाणीकरण टैग। छेड़छाड़ होने पर तुरंत अस्वीकार।
- **स्वचालित-समाप्ति क्लिपबोर्ड गार्ड (`clip`)**:
  - **मूल Win32 एकीकरण**: बैकऑफ के साथ Windows क्लिपबोर्ड API (`OpenClipboard`, `EmptyClipboard`, `SetClipboardData`, `CloseClipboard`) को सीधे नियंत्रित करता है।
  - **इतिहास और क्लाउड सिंक निषेध**: Win+V इतिहास और क्लाउड में जाने से रोकने के लिए Windows 10/11 गोपनीयता प्रारूप इंजेक्ट करता है।
  - **निरंतर-समय सत्यापन**: शाखाहीन SHA-256 तुलना (`constant_time_eq_32`) यह सुनिश्चित करती है कि केवल संरक्षित डेटा ही मिटाया जाए।
  - **दृश्य उलटी गिनती और त्वरित सफाई**: टर्मिनल प्रगति बार (`[████████░░] 12s remaining`), गैर-अवरोधक Enter कुंजी और मूक मोड (`--silent`)।
  - **प्रत्यक्ष आदेश एकीकरण**: `decrypt`, `extract`, `totp code` आदि पर `--clip` और `--clip-ttl <sec>` उपलब्ध।
- **RFC 6238 TOTP 2FA वॉल्ट (`totp`)**:
  - **शून्य बाहरी निर्भरता**: बेस32, RFC 3174 SHA-1 और RFC 2104 HMAC 100% परीक्षण पास।
  - **हार्डवेयर बाइंडिंग और AEAD संरक्षण**: `.svault` कंटेनर में दोहरी सुरक्षा।
  - **Key URI अंतरसंक्रियता**: मानक `otpauth://totp/...` URI का पूर्ण समर्थन।
  - **समय-संरेखित सुरक्षा**: निरंतर-समय सत्यापन और सहिष्णुता विंडो ($\pm S$)।
- **पासवर्ड शक्ति और एन्ट्रापी लेखा परीक्षक (`audit`)**:
  - **शैनन एन्ट्रापी गणना**: $0.0 \le H \le 8.0$ प्रति बाइट, कुल बिट्स और वर्ण स्थान।
  - **कमजोर पैटर्न का पता लगाना**: अनुक्रमिक वर्ण, दोहराव, कीबोर्ड पैटर्न और लीटस्पीक शब्दकोश।
  - **क्रैकिंग समय अनुमान**: ऑनलाइन दर-सीमित (100/सेकंड), Argon2id ($10^3$/सेकंड) और GPU क्लस्टर ($10^{10}$/सेकंड)।
  - **स्टेग्नोग्राफी वाहक विश्लेषण**: PNG, WAV, BMP LSB और ची-स्क्वायर ($\chi^2$) परीक्षण।
- **शमीर गुप्त साझाकरण ($M$-of-$N$)**:
  - **निरंतर-समय क्षेत्र अंकगणित**: $\text{GF}(256)$ पर तालिका रहित शाखाहीन गुणन और व्युत्क्रमण ($a^{-1} = a^{254}$)।
  - **दोहरी-परत अखंडता**: SHA-256 गुप्त डाइजेस्ट और प्रति-शेयर CRC-32।
  - **लचीले प्रारूप**: ASCII आर्मर्ड ब्लॉक, एकल-पंक्ति स्ट्रिंग और संरचित JSON।
- **प्रशंसनीय इनकार दोहरे-पासवर्ड कंटेनर**:
  - **सहज डिक्रिप्शन**: `svault decrypt -p <passphrase>` आपूर्ति किए गए पासवर्ड से संबंधित स्लॉट को अनलॉक करता है।
  - **अप्रभेद्य छुपा हुआ स्लॉट**: कोई प्लेनटेक्स्ट हेडर नहीं; पिछला भाग अधिकतम एन्ट्रापी (~8.0 बिट्स/बाइट) प्रस्तुत करता है।
  - **आकार भ्रम पैडिंग (`--padding <bytes>`)**: आकार विश्लेषण को रोकने के लिए CSPRNG यादृच्छिक पैडिंग।
- **हार्डवेयर / सत्र बाइंडिंग (`--dpapi`)** — Windows DPAPI द्वारा सुरक्षित ताकि डिक्रिप्शन मूल Windows उपयोगकर्ता प्रोफ़ाइल तक सीमित रहे।
- **सक्रिय मेमोरी शून्यीकरण (`zeroize`)** — ड्रॉप होने पर मेमोरी को शून्य से अधिलेखित किया जाता है।
- **दोषरहित PNG स्टेग्नोग्राफी (`embed` / `extract`)** — पूर्ण CRC-32 सत्यापन के साथ `IEND` से पहले `svLt` चंक जोड़ता है।
- **WAV ऑडियो स्टेग्नोग्राफी (`embed-wav` / `extract-wav`)**:
  - **सब-चंक्स मोड (`--mode chunk`)**: CRC-32 के साथ `svLt` मेटाडेटा।
  - **16-बिट PCM LSB मोड (`--lsb`)**: बिना ध्वनि परिवर्तन और फ़ाइल आकार बदले नमूनों का न्यूनतम बिट बदलता है।
- **BMP 24-बिट पिक्सेल LSB स्टेग्नोग्राफी (`embed-bmp` / `extract-bmp`)**:
  - **पंक्ति पैडिंग संरक्षण**: 4-बाइट संरेखण पैडिंग को नुकसान पहुंचाए बिना केवल R, G, B चैनलों में डेटा छुपाता है।
  - **12-बाइट छेड़छाड़-रोधी लिफाफा**: `[svLt: 4B][len: 4B LE][payload: NB][crc32: 4B LE]`।
- **कॉची रीड-सोलोमन त्रुटि-सुधार आर्मर (`armor` / `dearmor` / `repair`)**:
  - **$\text{GF}(256)$ कॉची MDS कोड**: $[I_K; A]$ जनरेटर मैट्रिक्स। $K+M$ में से कोई भी $K$ बरकरार स्ट्रिप्स पूरे डेटा का पुनर्निर्माण कर सकती हैं।
  - **प्रति-पट्टी CRC-32 और SHA-256**: सटीक क्षति पहचान और कंटेनर प्रमाणीकरण।
  - **स्व-उपचार मरम्मत (`repair`)**: क्षतिग्रस्त स्ट्रिप्स का पुनर्निर्माण और नई फ़ाइल निर्यात।
- **निर्देशिका और बहु-फ़ाइल पैकिंग (`pack-dir` / `unpack-dir`)**:
  - **`SVAR` बाइनरी प्रारूप**: 18-बाइट हेडर, SHA-256 डाइजेस्ट और 8-बाइट CRC-32 चेकसम।
  - **ज़िप स्लिप रोकथाम**: `..`, पूर्ण/UNC पथ और आरक्षित डिवाइस नामों को अस्वीकार करता है।
  - **संपीड़न बम रक्षा**: 8 GiB कुल और 4 GiB फ़ाइल आकार सीमा।
- **वाहक क्षमता अनुमान (`capacity`)** — `.bmp`, `.wav`, `.png`, `.mp3` में वास्तविक उपयोगी क्षमता की गणना करता है।
- **शून्य-ज्ञान हेडर निरीक्षण (`inspect`)** — डिक्रिप्ट किए बिना कंटेनर संस्करण, DPAPI ध्वज, और साल्ट की जांच करता है।
- **समय-लॉक और समाप्ति नीतियां (`policy`)**:
  - **प्रमाणित नीति हेडर (`SVPO`)**: समय टिकटों और विवरण के साथ 28-बाइट हेडर।
  - **AEAD AAD बाइंडिंग**: ChaCha20-Poly1305 के साथ अतिरिक्त प्रमाणित डेटा (`aad`) के रूप में इंजेक्ट किया जाता है।
- **की-फ़ाइल + पासवर्ड व्युत्पत्ति (`keyfile`)** — 64 KiB बफ़र में USB कुंजी को प्रोसेस कर Argon2id को 256-बिट सीड प्रदान करता है।
- **खंडित स्ट्रीमिंग एन्क्रिप्शन (`stream`)** — बड़ी फ़ाइलों के लिए $O(1)$ मेमोरी स्ट्रीमिंग।
- **स्टेगो वाहक अंतर रिपोर्ट (`compare`)** — MSE, PSNR, SNR और शैनन एन्ट्रापी अंतर $\Delta H$ की तुलना करता है।
- **स्व-विनाश और डेड-मैन स्विच (`guard`)** — असफल प्रयासों पर 3-चरणीय श्रेडिंग।
- **पासवर्ड जनरेटर (`keygen`)** — BIP-39 डाइसवेयर, अस्पष्टता-रहित पासवर्ड और क्रिप्टोग्राफ़िक टोकन।
- **इंटरएक्टिव टर्मिनल वॉल्ट शैल (`repl`)** — मेमोरी में कुंजी-मान वॉल्ट शैल।
- **3-पास सुरक्षित फ़ाइल श्रेडर (`shred`)** — `0x00`, `0xFF` और यादृच्छिक बाइट्स के साथ ओवरराइट।
- **एकल स्थिर बाइनरी** — बिना बाहरी निर्भरता के संकलित।

</details>

---

## 🚀 त्वरित शुरुआत और CLI कार्यप्रवाह

<details open>
<summary><b>🚀 त्वरित शुरुआत और CLI कार्यप्रवाह (विस्तार / संक्षिप्त करने के लिए श्रेणी पर क्लिक करें)</b></summary>
<br>

<details open>
<summary><b>🔐 1. दोहरी-परत एन्क्रिप्शन और प्रशंसनीय इनकार डिकॉय वॉल्ट (#1 - #6)</b></summary>
<br>

```bash
# 1. पासवर्ड और Windows DPAPI हार्डवेयर बाइंडिंग के साथ फ़ाइल एन्क्रिप्ट करें
svault encrypt -i wallet-seed.txt -o wallet.svault -p "your-strong-passphrase" --dpapi

# 2. गुप्त और डिकॉय दोनों डेटा युक्त प्रशंसनीय इनकार वॉल्ट एन्क्रिप्ट करें
svault encrypt -i classified.txt --decoy shopping-list.txt -o deniable.svault \
  -p "primary-secret-pass" --decoy-passphrase "decoy-harmless-pass" --padding 512

# 3. डिकॉय पासवर्ड से डिक्रिप्ट करें (केवल हानिरहित डेटा सामने आता है)
svault decrypt -i deniable.svault -o revealed.txt -p "decoy-harmless-pass"
# मुख्य पासवर्ड से डिक्रिप्ट करें (असली गुप्त डेटा पुनर्प्राप्त होता है)
svault decrypt -i deniable.svault -o restored.txt -p "primary-secret-pass"

# 4. डिक्रिप्ट किए बिना वॉल्ट मेटाडेटा का निरीक्षण करें (.svault, .png, .wav या .bmp)
svault inspect deniable.svault

# 5. PNG छवि के भीतर दोहरे-पासवर्ड वाले डिकॉय वॉल्ट को छुपाएं
svault embed -c wallpaper.png -s classified.txt --decoy shopping-list.txt -o wallpaper-stego.png \
  -p "primary-secret-pass" --decoy-passphrase "decoy-harmless-pass"

# 6. PNG छवि से गुप्त फ़ाइल निकालें (मुख्य या डिकॉय पासवर्ड से)
svault extract -c wallpaper-stego.png -o restored-seed.txt -p "primary-secret-pass"
svault extract -c wallpaper-stego.png -o decoy-seed.txt --decoy-passphrase "decoy-harmless-pass"
```

</details>

<details open>
<summary><b>🖼️ 2. दोषरहित मीडिया स्टेग्नोग्राफी: PNG, WAV, BMP, MP3 और क्षमता (#7 - #13)</b></summary>
<br>

```bash
# 7. WAV ऑडियो फ़ाइल में डेटा छुपाएं (RIFF सब-चंक्स या 16-बिट PCM LSB)
svault embed-wav -c track.wav -s classified.txt -o track-lsb.wav -p "primary-secret-pass" --lsb

# 8. WAV ऑडियो फ़ाइल से डेटा निकालें (स्वचालित पहचान)
svault extract-wav -c track-lsb.wav -o restored-audio.txt -p "primary-secret-pass"

# 9. स्टेग्नोग्राफी वाहक क्षमता का अनुमान लगाएं (.bmp, .wav, .png या .mp3)
svault capacity landscape.bmp
svault capacity track.wav --json
svault capacity song.mp3

# 10. पिक्सेल LSB द्वारा 24-बिट BMP छवि में गुप्त फ़ाइल छुपाएं
svault embed-bmp -c landscape.bmp -s classified.txt -o landscape-stego.bmp -p "primary-secret-pass"

# 11. BMP छवि से डेटा सीधे स्वचालित-समाप्ति क्लिपबोर्ड पर निकालें (15 सेकंड)
svault extract-bmp -c landscape-stego.bmp -p "primary-secret-pass" --clip --clip-ttl 15

# 12. MP3 ऑडियो फ़ाइल में डेटा छुपाएं (ID3v2 PRIV टैग या इंटर-फ़्रेम पैडिंग)
svault embed-mp3 -c song.mp3 -s classified.txt -o song-stego.mp3 -p "primary-secret-pass" --mode id3v2
svault embed-mp3 -c song.mp3 -s classified.txt -o song-frame.mp3 -p "primary-secret-pass" --mode frame

# 13. MP3 फ़ाइल से डेटा निकालें और डिक्रिप्ट करें
svault extract-mp3 -c song-stego.mp3 -o restored-mp3.txt -p "primary-secret-pass"
```

</details>

<details open>
<summary><b>🧩 3. सुरक्षित श्रेडिंग, शमीर गुप्त साझाकरण और एन्ट्रापी लेखा परीक्षा (#12 - #16)</b></summary>
<br>

```bash
# 12. मूल प्लेनटेक्स्ट फ़ाइल को सुरक्षित रूप से 3-पास श्रेड करें
svault shred classified.txt --passes 3

# 13. मास्टर रिकवरी कुंजी को 3-of-5 शमीर शेयरों में विभाजित करें
svault split -s "your-master-seed-or-secret" -m 3 -n 5 -o shares/share

# 14. मूल डेटा पुनर्प्राप्त करने के लिए किन्हीं 3 शेयरों को संयोजित करें
svault combine shares/share_1.share shares/share_3.share shares/share_5.share -o restored.txt

# 15. पासवर्ड शक्ति, शैनन एन्ट्रापी और क्रैकिंग समय का विश्लेषण करें
svault audit -p "Correct-Horse-Battery-Staple-2026!"

# 16. स्टेगो वाहक छवि या कंटेनर में असामान्यताओं की जांच करें
svault audit wallpaper-stego.png --json
```

</details>

<details open>
<summary><b>⏱️ 4. RFC 6238 TOTP 2FA वॉल्ट और क्लिपबोर्ड गार्ड (#17 - #23)</b></summary>
<br>

```bash
# 17. Base32 या otpauth:// URI के माध्यम से 2FA क्रेडेंशियल जोड़ें
svault totp add github --secret "JBSWY3DPEHPK3PXP" --issuer "GitHub" --vault totp.svault -p "vault-pass"
svault totp add --uri "otpauth://totp/Google:alice?secret=JBSWY3DPEHPK3PXP&issuer=Google" --vault totp.svault -p "vault-pass"

# 18. दृश्य प्रगति बार के साथ लाइव 2FA OTP कोड जनरेट करें
svault totp code github --vault totp.svault -p "vault-pass"
svault totp code github --vault totp.svault -p "vault-pass" --json

# 19. समय सहिष्णुता विंडो (+/- 1 कदम) के साथ OTP कोड सत्यापित करें
svault totp verify github 123456 --skew 1 --vault totp.svault -p "vault-pass"

# 20. 2FA खातों की सूची बनाएं और निर्यात करें
svault totp list --vault totp.svault -p "vault-pass"
svault totp export github --vault totp.svault -p "vault-pass"

# 21. 15-सेकंड स्वचालित-समाप्ति के साथ क्लिपबोर्ड पर कॉपी करें
svault clip copy "my-super-secret-password" --ttl 15
svault clip copy "my-super-secret-password" --ttl 15 --silent

# 22. क्लिपबोर्ड स्थिति जांचें या मैन्युअल रूप से साफ़ करें
svault clip status
svault clip clear

# 23. सीधे सुरक्षित क्लिपबोर्ड पर डिक्रिप्ट करें (टर्मिनल या डिस्क पर नहीं)
svault decrypt -i secret.svault -p "vault-pass" --clip --clip-ttl 30
svault totp code github --vault totp.svault -p "vault-pass" --clip --clip-ttl 15
```

</details>

<details open>
<summary><b>🛡️ 5. कॉची रीड-सोलोमन आर्मर और निर्देशिका पैकिंग (#24 - #30)</b></summary>
<br>

```bash
# 24. कॉची रीड-सोलोमन पैरिटी स्ट्रिप्स के साथ .svault को ASCII आर्मर दें (.svault.asc)
svault armor -i secret.svault -o secret.svault.asc -k 4 -m 2

# 25. ASCII आर्मर्ड फ़ाइल को वापस .svault कंटेनर में बदलें
svault dearmor -i secret.svault.asc -o recovered.svault

# 26. क्षतिग्रस्त .svault.asc फ़ाइल को पैरिटी से स्व-उपचारित करें
svault repair -i corrupted.svault.asc -o repaired.svault.asc --json
svault repair -i corrupted.svault.asc -o direct_recovered.svault --binary

# 27. आर्मर्ड कंटेनर स्ट्रिप्स और अखंडता की जांच करें
svault inspect secret.svault.asc
svault audit secret.svault.asc --json

# 28. पूरी निर्देशिका ट्री को एन्क्रिप्टेड .svault कंटेनर में पैक करें
svault pack-dir -i ./my_project -o project.svault -p "pack-passphrase" --list

# 29. निर्देशिका को स्टेगो वाहक (PNG, WAV, BMP, MP3) या ASCII आर्मर में पैक करें
svault pack-dir -i ./my_project -o project.png -p "pack-passphrase" --carrier cover.png
svault pack-dir -i ./my_project -o project.svault.asc -p "pack-passphrase" --armor

# 30. निर्देशिका अनपैक करें, मैनिफ़ेस्ट जांचें या हैश सत्यापित करें
svault unpack-dir -i project.svault -p "pack-passphrase" --list
svault unpack-dir -i project.svault -p "pack-passphrase" --verify-only
svault unpack-dir -i project.svault -o ./restored_project -p "pack-passphrase" --overwrite
```

</details>

<details open>
<summary><b>⏳ 6. समय-लॉक नीतियां, USB की-फ़ाइलें और खंडित स्ट्रीमिंग (#31 - #42)</b></summary>
<br>

```bash
# 31. समय-लॉक एस्क्रो नीति के साथ एन्क्रिप्ट करें (भविष्य की तारीख से पहले नहीं खोला जा सकता)
svault encrypt -i escrow.txt -o escrow.svault -p "vault-pass" --not-before "2026-12-31T00:00:00Z" --policy-desc "Year-End Escrow"

# 32. स्वतः समाप्ति नीति के साथ एन्क्रिप्ट करें (2 घंटे या विशिष्ट तिथि में समाप्त)
svault encrypt -i token.txt -o token.svault -p "vault-pass" --expires-in 2h --policy-desc "Session Token"
svault encrypt -i doc.txt -o doc.svault -p "vault-pass" --expires-at "2026-10-15"

# 33. डिक्रिप्ट किए बिना नीति मेटाडेटा का निरीक्षण करें
svault inspect escrow.svault
svault inspect escrow.svault --json

# 34. संदर्भ समय के विरुद्ध डिक्रिप्शन का परीक्षण करें
svault decrypt -i escrow.svault -o restored.txt -p "vault-pass" --at-time "2027-01-01"

# 35. क्रिप्टोग्राफ़िक USB की-फ़ाइल उत्पन्न करें (CSPRNG, डिफ़ॉल्ट 64 बाइट्स)
svault keyfile generate -o usb_token.key --bytes 64

# 36. की-फ़ाइल फ़िंगरप्रिंट और शैनन एन्ट्रापी की जांच करें
svault keyfile inspect usb_token.key
svault keyfile inspect usb_token.key --json
svault keyfile fingerprint usb_token.key

# 37. 2FA (पासवर्ड + की-फ़ाइल) के साथ एन्क्रिप्ट और डिक्रिप्ट करें
svault encrypt -i secret.txt -o sealed.svault -p "master-pass" -k usb_token.key
svault decrypt -i sealed.svault -o restored.txt -p "master-pass" -k usb_token.key

# 38. बिना पासवर्ड केवल की-फ़ाइल एन्क्रिप्शन
svault encrypt -i token.txt -o hardware.svault -k usb_token.key
svault decrypt -i hardware.svault -o restored.txt -k usb_token.key

# 39. की-फ़ाइल 2FA के साथ निर्देशिका पैक और अनपैक करें
svault pack-dir -i ./confidential -o archive.svault -p "pack-pass" -k usb_token.key
svault unpack-dir -i archive.svault -o ./unpacked -p "pack-pass" -k usb_token.key

# 40. चंक स्ट्रीमिंग के साथ मल्टी-गीगाबाइट फ़ाइल को एन्क्रिप्ट करें (डिफ़ॉल्ट 4 MiB)
svault stream encrypt -i large_dataset.iso -o large_dataset.svault -p "stream-pass"
svault encrypt -i database.backup -o db.svault -p "stream-pass" --stream --chunk-size 8M

# 41. स्ट्रीमिंग कंटेनर को डिक्रिप्ट करें
svault decrypt -i large_dataset.svault -o restored.iso -p "stream-pass"
svault stream decrypt -i db.svault -o restored_db.backup -p "stream-pass"

# 42. स्ट्रीमिंग कंटेनर मेटाडेटा का निरीक्षण करें
svault stream inspect large_dataset.svault
svault inspect large_dataset.svault --json
```

</details>

<details open>
<summary><b>🚨 7. स्टेगो अंतर रिपोर्ट, डेड-मैन स्विच और पासवर्ड जनरेटर (#43 - #53)</b></summary>
<br>

```bash
# 43. मूल वाहक की स्टेगो वाहक से तुलना करें (PNG, BMP, WAV या बाइनरी)
svault compare cover.bmp stego.bmp
svault compare cover.png stego.png --json
svault diff original.wav stego.wav --detailed

# 44. 3-प्रयास स्व-विनाश गार्ड और डेड-मैन स्विच के साथ वॉल्ट को सुरक्षित करें
svault encrypt -i secret.txt -o guarded.svault -p "vault-pass" --max-attempts 3 --dead-man 7d --guard-companion

# 45. किसी मौजूदा वाहक या वॉल्ट फ़ाइल पर गार्ड लगाएं
svault guard arm -t stego.png --max-attempts 3 --companion
svault guard arm -t vault.svault --max-attempts 5 --dead-man 24h

# 46. गार्ड स्थिति और शेष प्रयासों की जांच करें
svault guard status -t guarded.svault
svault guard status -t guarded.svault --json

# 47. डेड-मैन स्विच को नवीनीकृत करने या काउंटर रीसेट करने के लिए चेक-इन करें
svault guard checkin -t guarded.svault --interval 30d
svault guard reset -t guarded.svault

# 48. गार्ड को निष्क्रिय करें या आपातकालीन मल्टी-पास श्रेडिंग ट्रिगर करें
svault guard disarm -t guarded.svault
svault guard trigger -t guarded.svault --force --passes 3

# 49. 6-शब्दों का BIP-39 डाइसवेयर रिकवरी पासवर्ड बनाएं
svault keygen --words 6

# 50. संख्याओं और बड़े अक्षरों के साथ अनुकूलित डाइसवेयर बनाएं
svault keygen --words 4 --separator "." --capitalize --number

# 51. 24-वर्णों का पासवर्ड उत्पन्न करें (अस्पष्टता फ़िल्टर और एन्ट्रापी के साथ)
svault keygen --length 24 --exclude-ambiguous --entropy

# 52. मास्टर सीड और सेवा संदर्भ से निर्धारक पासवर्ड व्युत्पत्ति
svault keygen --words 6 --seed "master-recovery-seed" --context "github-token"

# 53. 32-बाइट क्रिप्टोग्राफ़िक यादृच्छिक टोकन उत्पन्न करें और क्लिपबोर्ड पर कॉपी करें
svault keygen --bytes 32 --base64 --clip --clip-ttl 30
svault keygen --bytes 20 --base32 --json
```

</details>

<details open>
<summary><b>💻 8. कुंजी रोटेशन, कैनरी अखंडता और REPL शैल (#54 - #63)</b></summary>
<br>

```bash
# 54. नए पासवर्ड, साल्ट और नॉनस के साथ कंटेनर कुंजी को री-की करें
svault rotate -i vault.svault -o rotated.svault -p "old-secret" -n "new-secret"

# 55. कंटेनर या वाहक को इन-प्लेस परमाणु रूप से रोटेट करें
svault rotate -i vault.svault --in-place -p "old-secret" -n "new-secret"
svault rotate -i stego.bmp --in-place -p "old-pass" -n "new-pass"

# 56. स्टेगो वाहक क्रेडेंशियल रोटेट करें (PNG, WAV, BMP या ASCII आर्मर)
svault rotate -i carrier.png -o rotated.png -p "old-pass" -n "new-pass"
svault rotate -i carrier.asc -o rotated.asc -p "old-pass" -n "new-pass"

# 57. DPAPI हार्डवेयर बाइंडिंग टॉगल या नीति साफ़ करते हुए रोटेट करें
svault rotate -i vault.svault -o dpapi_vault.svault -p "old-pass" -n "new-pass" --dpapi
svault rotate -i locked.svault -o unlocked.svault -p "old-pass" -n "new-pass" --clear-policy --json

# 58. लक्ष्य निर्देशिका के लिए अलग अखंडता कैनरी मैनिफ़ेस्ट आरंभ करें
svault canary init -d ./vaults
svault canary init -d ./vaults -p "canary-auth-secret" --json

# 59. डिस्क फ़ाइलों में अनधिकृत परिवर्तनों के विरुद्ध कैनरी की पुष्टि करें
svault canary verify -d ./vaults
svault canary verify -d ./vaults -p "canary-auth-secret" --strict --json

# 60. मेमोरी में की-वैल्यू वॉल्ट इंटरएक्टिव REPL शैल प्रारंभ करें
svault repl -v myvault.svault -p "session-pass"

# 61. --exec के माध्यम से बैच REPL कमांड निष्पादित करें
svault repl -v myvault.svault -p "session-pass" --exec "set api_key sk_live_xyz --tag prod; set db_pass secret; save"

# 62. स्वचालित-समाप्ति क्लिपबोर्ड संरक्षण के साथ सीधे गुप्त जानकारी देखें
svault repl -v myvault.svault -p "session-pass" --exec "get api_key --clip --clip-ttl 15"

# 63. केवल-पठन मोड में REPL खोलें या JSON में निर्यात करें
svault repl -v myvault.svault -p "session-pass" --readonly --exec "list" --json
svault repl -v myvault.svault -p "session-pass" --exec "export ./backup.json; exit"
```

</details>

<details open>
<summary><b>🔑 9. FIDO2 / Windows Hello हार्डवेयर कुंजी क्रेडेंशियल बाइंडिंग (#64 - #70)</b></summary>
<br>

```bash
# 64. होस्ट प्लेटफ़ॉर्म हार्डवेयर टोकन क्षमताओं की जांच करें (Windows Hello, WebAuthn API)
svault fido2 status
svault fido2 status --json

# 65. FIDO2 USB कुंजी या Windows Hello क्रेडेंशियल पंजीकृत करें
svault fido2 enroll yubikey-5c --type usb --user alice --output ./yubikey.json
svault fido2 enroll hello-tpm --type hello --pin 849201 --json

# 66. प्रमाणक पुष्टि का परीक्षण करें और PRF व्युत्पत्ति फ़िंगरप्रिंट सत्यापित करें
svault fido2 test ./yubikey.json
svault fido2 test ./yubikey.json --json

# 67. FIDO2 क्रेडेंशियल और पासवर्ड के साथ कंटेनर को एन्क्रिप्ट करें
svault encrypt -i secret.txt -o sealed.svault --fido2-cred ./yubikey.json -p "master-pass"

# 68. पंजीकृत हार्डवेयर क्रेडेंशियल का उपयोग करके कंटेनर डिक्रिप्ट करें
svault decrypt -i sealed.svault -o restored.txt --fido2-cred ./yubikey.json -p "master-pass"

# 69. मल्टी-फैक्टर 2FA: की-फ़ाइल + FIDO2 भौतिक टोकन (बिना पासवर्ड)
svault encrypt -i secret.txt -o mfa.svault -k usb_token.key --fido2-cred ./yubikey.json
svault decrypt -i mfa.svault -o restored.txt -k usb_token.key --fido2-cred ./yubikey.json

# 70. FIDO2 हार्डवेयर बाइंडिंग जोड़ने या हटाने के लिए कंटेनर रोटेट करें
svault rotate -i sealed.svault --in-place -p "old-pass" -n "new-pass" --fido2 --fido2-cred ./yubikey.json
svault rotate -i sealed.svault --in-place -p "new-pass" -n "plain-pass" --no-fido2 --fido2-cred ./yubikey.json
```

</details>

<details open>
<summary><b>⚛️ 10. पोस्ट-क्वांटम हाइब्रिड कुंजी इनकैप्सुलेशन (X25519 + ML-KEM-768) (#71 - #74)</b></summary>
<br>

```bash
# 71. पोस्ट-क्वांटम हाइब्रिड कुंजी युग्म जनरेट करें (X25519 + ML-KEM-768)
svault kem keygen -p recipient.pub -s recipient.key
svault kem keygen -p recipient.pub -s recipient.key --json

# 72. प्राप्तकर्ता की सार्वजनिक कुंजी के लिए गोपनीय फ़ाइल सील करें
svault kem seal -i classified.txt -o sealed.svault.pq -k recipient.pub
svault kem seal -i classified.txt -o sealed.asc -k recipient.pub --armor --json

# 73. पोस्ट-क्वांटम कंटेनर मेटाडेटा का निरीक्षण करें (क्षणिक कुंजी, ML-KEM आकार, CRC-32)
svault kem inspect -i sealed.svault.pq
svault kem inspect -i sealed.asc --json

# 74. प्राप्तकर्ता की निजी कुंजी का उपयोग करके पोस्ट-क्वांटम वॉल्ट खोलें और डिक्रिप्ट करें
svault kem open -i sealed.svault.pq -o restored.txt -k recipient.key
svault kem open -i sealed.asc -o restored.txt -k recipient.key --json
```

</details>

</details>

---

## 🔒 मेमोरी सुरक्षा और संरक्षण अपरिवर्तनीय

<details open>
<summary><b>🔒 मेमोरी सुरक्षा और संरक्षण अपरिवर्तनीय</b></summary>
<br>

- **100% सुरक्षित Rust और निरंतर-समय क्रिप्टोग्राफी**: डेटा पथों में कोई `unsafe` ब्लॉक नहीं; समय-आधारित साइड-चैनल हमलों को रोकने के लिए शाखाहीन गैलोइस फ़ील्ड अंकगणित।
- **सक्रिय मेमोरी शून्यीकरण**: मध्यवर्ती कुंजी शेड्यूल्स, प्लेनटेक्स्ट बफ़र्स और PRF बीज ड्रॉप होने पर `zeroize` के माध्यम से कंपाइलर-बाड़ के साथ मेमोरी से शून्य हो जाते हैं।
- **हार्डवेयर प्रोफ़ाइल से बंधा**: Windows DPAPI रैपिंग सुनिश्चित करती है कि सिफरटेक्स्ट मूल मशीन और उपयोगकर्ता सत्र के बाहर डिक्रिप्ट नहीं किया जा सकता।
- **ज़िप स्लिप और संपीड़न बम रक्षा**: कैनोनिकल सापेक्ष पथ, सख्त सीमाएं और आवंटन सीमाएं संसाधन थकावट को रोकती हैं।

</details>

---

## 📄 लाइसेंस और आभार

<details open>
<summary><b>📄 लाइसेंस और आभार</b></summary>
<br>

Copyright 2026 **GHSFS** ([https://github.com/GHSFS](https://github.com/GHSFS)).

**Apache License, Version 2.0** ([`LICENSE`](../../LICENSE)) के तहत लाइसेंस प्राप्त। Apache License 2.0 की धारा 4(d) के अनुसार, पुनर्वितरण या व्युत्पन्न कार्यों में [`NOTICE`](../../NOTICE) फ़ाइल में दिए गए आभार नोटिस को बनाए रखना अनिवार्य है।

</details>
