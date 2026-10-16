<div align="center">

<p align="center">
  <a href="../../README.md">🇺🇸 English</a> · <a href="./ko.md">🇰🇷 한국어</a> · <a href="./zh-CN.md">🇨🇳 中文</a> · <a href="./es.md">🇪🇸 Español</a> · <a href="./hi.md">🇮🇳 हिन्दी</a><br />
  <a href="./ar.md">🇸🇦 العربية</a> · <a href="./pt-BR.md">🇧🇷 Português</a> · <a href="./ru.md">🇷🇺 Русский</a> · <a href="./fr.md">🇫🇷 Français</a> · <strong>🇮🇩 Bahasa Indonesia</strong>
</p>

# shadow-vault (`svault`)

> Brankas terenkripsi zero-trust dengan steganografi dan pengikatan perangkat keras berlapis ganda — sembunyikan file sensitif di dalam media PNG/audio biasa, segel dengan Argon2id + ChaCha20-Poly1305 + Windows DPAPI, atau sematkan brankas umpan penyangkalan yang masuk akal dengan kata sandi ganda.

[![Build](https://github.com/GHSFS/shadow-vault/actions/workflows/build.yml/badge.svg)](https://github.com/GHSFS/shadow-vault/actions/workflows/build.yml)
[![Tests](https://github.com/GHSFS/shadow-vault/actions/workflows/test.yml/badge.svg)](https://github.com/GHSFS/shadow-vault/actions/workflows/test.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](../../LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20x64-0078D6)](#panduan-cepat)

</div>

---

### Gambaran Umum Proyek

`shadow-vault` (`svault.exe`) adalah toolkit kriptografi dan steganografi biner tunggal tanpa dependensi eksternal yang ditulis dalam Rust, dirancang untuk melindungi aset bernilai tinggi:

1. **Enkripsi Terautentikasi Lapisan Ganda (`SVLT` v1/v2)** — menggabungkan derivasi kunci **Argon2id** (memori-keras) + **ChaCha20-Poly1305** AEAD dengan pengikatan perangkat keras opsional **Windows DPAPI (`CryptProtectData`)**.
2. **Penyangkalan yang Masuk Akal & Brankas Umpan (`src/decoy.rs`)** — menyematkan rahasia utama dan muatan umpan dalam satu wadah; di bawah paksaan, kata sandi umpan hanya membuka data yang tidak berbahaya.
3. **Steganografi Media Tanpa Kehilangan Kualitas**:
   - **Gambar PNG**: menyuntikkan chunk `svLt` sebelum `IEND` dengan validasi CRC-32 IEEE 802.3.
   - **Audio WAV**: mendukung sub-chunk RIFF dan penggantian LSB pada sampel PCM 16-bit.
   - **Gambar BMP**: modulasi LSB pada saluran RGB 24-bit dengan pemeliharaan padding baris 4-byte.
   - **Audio MP3**: penyembunyian di dalam bingkai tag ID3v2 `PRIV` atau padding frame MPEG.
4. **Estimasi Kapasitas Universal (`capacity`)** — perhitungan kapasitas muatan pada `.bmp`, `.wav`, `.png`, `.mp3`.
5. **Pembagian Rahasia Shamir (`M-dari-N`, `src/shamir.rs`)** — aritmatika waktu-konstan pada $\text{GF}(256)$ untuk membagi kunci menjadi $N$ bagian dengan ambang batas $M$.
6. **Auditor Entropi dan Kekuatan Kata Sandi (`src/audit.rs`)** — perhitungan entropi Shannon dan deteksi pola rentan.
7. **Brankas TOTP 2FA RFC 6238 (`src/totp.rs`)** — autentikator 2FA lokal mandiri yang kebal terhadap serangan waktu (timing attacks).
8. **Penjaga Papan Klip dengan Masa Kedaluwarsa (`src/clipboard_guard.rs`)** — mencegah riwayat Windows 10/11 dan penghapusan otomatis setelah batas waktu TTL.
9. **Lapisan Koreksi Kesalahan Cauchy Reed-Solomon (`src/armor.rs`)** — rekonstruksi data penuh dari $K$ fragmen utuh dari total $K+M$.
10. **Pengarsipan Direktori dengan Manifes Aman (`src/archive.rs`)** — perlindungan terhadap Zip Slip / Zip Bomb dan verifikasi hash SHA-256 tiap file.
11. **Derivasi 2FA dengan File Kunci (`src/keyfile.rs`)** — pengikatan token fisik USB dengan pra-hashing streaming 64 KiB HMAC-SHA256.
12. **Enkripsi Streaming Berkelanjutan (`src/stream.rs`)** — pemrosesan blok 4 MiB dalam memori konstan $O(1)$ untuk file multi-gigabita.
13. **Laporan Perbedaan Visual dan Statistik (`src/diff.rs`)** — evaluasi metrik MSE, PSNR, SNR, dan pergeseran entropi.
14. **Saklar Tombol Mati & Penghancuran Otomatis (`src/guard.rs`)** — penghancuran kriptografi 3 tahap pada file setelah $K$ kali kesalahan kata sandi berturut-turut.
15. **Generator BIP-39 dan CSPRNG (`src/passgen/`)** — pembuatan frasa mnemonik 2.048 kata dan token acak berkekuatan tinggi.
16. **Output JSON Terstruktur Terpadu (`--json`)** — siap untuk integrasi pipa otomatisasi dan CI/CD.
17. **Rotasi Kunci Wadah (`rotate`)** — enkripsi ulang yang aman dengan salt dan nonce baru tanpa menulis teks biasa ke disk.
18. **Kenari Integritas Direktori (`canary`)** — pemantauan pohon file terhadap gangguan atau modifikasi yang tidak sah.
19. **Pengikatan Perangkat Keras FIDO2 dan Windows Hello (`src/hardware_token/`)** — dukungan kunci YubiKey dan biometrik TPM via CTAP2 PRF.
20. **Enkapsulasi Kunci Hibrida Pasca-Kuantum (`src/pq_kem/`)** — kombinasi X25519 dan standar NIST FIPS 203 ML-KEM-768.
21. **Pembersihan Memori Aktif (`zeroize`)** — penghapusan buffer sensitif dalam memori setelah digunakan.

### Panduan Cepat

```bash
# 1. Enkripsi file dengan kata sandi dan pengikatan perangkat keras DPAPI
svault encrypt -i wallet-seed.txt -o wallet.svault -p "kata-sandi-kuat" --dpapi

# 2. Buat brankas penyangkalan yang masuk akal (rahasia utama + umpan)
svault encrypt -i classified.txt --decoy shopping-list.txt -o deniable.svault \
  -p "sandi-utama" --decoy-passphrase "sandi-umpan" --padding 512

# 3. Dekripsi dengan kata sandi umpan
svault decrypt -i deniable.svault -o revealed.txt -p "sandi-umpan"

# 4. Periksa metadata wadah tanpa mendekripsi
svault inspect deniable.svault

# 5. Sembunyikan brankas di dalam gambar PNG
svault embed -c wallpaper.png -s classified.txt --decoy shopping-list.txt -o wallpaper-stego.png \
  -p "sandi-utama" --decoy-passphrase "sandi-umpan"

# 6. Ekstrak rahasia nyata dari gambar PNG
svault extract -c wallpaper-stego.png -o restored-seed.txt -p "sandi-utama"
```

### Lisensi dan Atribusi

Copyright 2026 **GHSFS** ([https://github.com/GHSFS](https://github.com/GHSFS)).

Didistribusikan di bawah **Apache License, Version 2.0** ([LICENSE](../../LICENSE)). Pemberitahuan atribusi harus dipertahankan sesuai dengan [NOTICE](../../NOTICE).
