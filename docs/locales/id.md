<div align="center">

<p align="center">
  <a href="../../README.md">🇺🇸 English</a> · <a href="./ko.md">🇰🇷 한국어</a> · <a href="./zh-CN.md">🇨🇳 中文</a> · <a href="./es.md">🇪🇸 Español</a> · <a href="./hi.md">🇮🇳 हिन्दी</a><br />
  <a href="./ar.md">🇸🇦 العربية</a> · <a href="./pt-BR.md">🇧🇷 Português</a> · <a href="./ru.md">🇷🇺 Русский</a> · <a href="./fr.md">🇫🇷 Français</a> · <strong>🇮🇩 Bahasa Indonesia</strong>
</p>

# shadow-vault (`svault`)

> Steganografi Zero-Trust dan brankas terenkripsi terikat-perangkat keras lapis ganda — sembunyikan file sensitif di dalam media PNG/audio biasa, segel dengan Argon2id + ChaCha20-Poly1305 + Windows DPAPI, atau sematkan brankas umpan penyangkalan yang masuk akal (Plausible Deniability) dengan kata sandi ganda.

[![Build](https://github.com/GHSFS/shadow-vault/actions/workflows/build.yml/badge.svg)](https://github.com/GHSFS/shadow-vault/actions/workflows/build.yml)
[![Tests](https://github.com/GHSFS/shadow-vault/actions/workflows/test.yml/badge.svg)](https://github.com/GHSFS/shadow-vault/actions/workflows/test.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](../../LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20x64-0078D6)](#-panduan-cepat-dan-alur-kerja-cli)

</div>

---

## 🛡️ Ringkasan dan Kemampuan Utama

<details open>
<summary><b>🛡️ Ringkasan dan Kemampuan Utama</b></summary>
<br>

`shadow-vault` (`svault.exe`) adalah kotak peralatan kriptografi dan steganografi biner tunggal tanpa dependensi eksternal yang ditulis dalam Rust, dirancang untuk operator yang membutuhkan perlindungan tingkat militer untuk file bernilai tinggi (frasa pemulihan, kunci privat, kredensial, catatan penelitian rahasia):

1. **Enkripsi Terautentikasi Berlapis Ganda (`SVLT` v1/v2)** — menggabungkan derivasi kunci dengan penguatan memori **Argon2id** + **ChaCha20-Poly1305** AEAD dengan pengikatan perangkat keras dan sesi pengguna opsional **Windows DPAPI (`CryptProtectData`)**. Bahkan jika penyerang mencuri file `.svault` dan kata sandi, brankas yang terikat DPAPI tidak dapat didekripsi di luar akun pengguna Windows asli Anda.
2. **Penyangkalan yang Masuk Akal & Brankas Umpan (`src/decoy.rs`)** — menyematkan rahasia utama tersembunyi (dibuka dengan kata sandi master) dan muatan umpan yang tidak berbahaya (dibuka dengan kata sandi umpan) dalam satu wadah. Di bawah paksaan, memberikan kata sandi umpan hanya membuka data umpan, sementara slot utama yang tersembunyi secara statistik tidak dapat dibedakan dari derau acak seragam (padding CSPRNG dan teks tersandi ChaCha20-Poly1305).
3. **Steganografi Media Tanpa Kehilangan (Lossless)** — menyembunyikan wadah terenkripsi di dalam media file biasa:
   - **Gambar PNG (`embed` / `extract`)**: menyuntikkan potongan tambahan pribadi `svLt` sebelum `IEND` dengan checksum IEEE 802.3 CRC-32 yang valid (mendukung penyematan brankas umpan langsung).
   - **File Audio WAV (`embed-wav` / `extract-wav`)**: mendukung sub-potongan RIFF/WAVE (`--mode chunk`) dan penggantian Least Significant Bit (LSB) sampel audio PCM 16-bit (`--lsb`) dengan validasi CRC-32.
   - **Gambar BMP (`src/bmp.rs`)**: memodulasi LSB di seluruh saluran piksel RGB 24-bit yang tidak dikompresi dengan pelestarian padding baris 4-byte yang ketat dan amplop 12-byte anti-rusak (`svLt`, panjang, muatan, CRC-32).
   - **File Audio MP3 (`src/mp3/`)**: menyembunyikan muatan di dalam bingkai tag pribadi ID3v2.3/ID3v2.4 (`PRIV`) atau padding antar-bingkai MPEG Audio Layer III dengan validasi sinkronisasi, pelestarian metadata (TIT2, TPE1) dan estimasi kapasitas.
4. **Estimasi Kapasitas Pembawa Universal (`capacity`)** — mengevaluasi ukuran total, kapasitas bita yang dapat digunakan, dan overhead steganografi pada pembawa `.bmp`, `.wav`, `.png`, dan `.mp3` secara presisi (`svault capacity <carrier> [--json]`).
5. **Pembagian Rahasia Shamir (`M-of-N`, `src/shamir.rs`)** — aritmatika medan berhingga $\text{GF}(256)$ waktu-konstan tanpa percabangan bersyarat. Membagi kunci pemulihan master, kata sandi, atau wadah menjadi $N$ bagian, membutuhkan sembarang $M$ bagian untuk merekonstruksi (`svault split` / `svault combine`). Mendukung teks lapis baja ASCII, string ringkas satu baris, dan JSON.
6. **Auditor Kekuatan Kata Sandi & Entropi Pembawa (`src/audit.rs`)** — mengevaluasi ketahanan kata sandi melalui bit entropi Shannon per bita, keragaman karakter, dan mendeteksi pola rentan (karakter berulang, urutan, pola papan ketik, leetspeak). Mengaudit potongan PNG, aliran WAV RIFF/LSB, LSB piksel BMP, dan wadah `.svault` (`svault audit <target>` / `svault audit -p <passphrase>`).
7. **Brankas RFC 6238 TOTP 2FA (`src/totp.rs`)** — penyimpan autentikasi dua faktor lokal terenkripsi tanpa dependensi eksternal, disegel dalam wadah `.svault`. Termasuk Base32 (RFC 4648), RFC 3174 SHA-1, RFC 2104 HMAC (SHA-1/256/512), pengurai URI `otpauth://totp/...`, verifikasi waktu-konstan, dan bilah hitung mundur terminal (`svault totp add`, `svault totp code`, `svault totp list`, `svault totp verify`).
8. **Penjaga Papan Klip Kedaluwarsa Otomatis (`src/clipboard_guard.rs`)** — menyalin kredensial dengan aman ke papan klip Windows dan menghapusnya setelah TTL yang dapat dikonfigurasi (mis. `--clip-ttl 15`). Menyuntikkan metadata privasi Windows 10/11 untuk mencegah riwayat (Win + V) dan sinkronisasi cloud, dengan verifikasi sidik jari SHA-256 waktu-konstan (`constant_time_eq_32`).
9. **Pelindung Koreksi Kesalahan Cauchy Reed-Solomon (`src/armor.rs`)** — menambahkan garis paritas dan ekspor/impor/perbaikan lapis baja ASCII `.svault.asc` untuk bertahan dari pembusukan bit (bit rot) atau gangguan transmisi. Menggunakan matriks generator Cauchy $[I_K; A]$ di atas $\text{GF}(256)$ dengan sifat MDS: SEMBARANG $K$ bagian utuh dari $K+M$ garis dapat merekonstruksi semua data asli (`svault repair`).
10. **Pengarsipan Direktori dan Manifes Multi-File (`src/archive.rs`)** — mengemas pohon direktori lengkap dengan kanonisasi jalur relatif, pencegahan Zip Slip, pertahanan bom dekompresi, manifes SHA-256 per file, dan pelestarian izin dalam satu wadah `SVLT` tersegel (`svault pack-dir` / `svault unpack-dir`).
11. **Derivasi Kunci Dua Faktor Keyfile + Kata Sandi (`src/keyfile.rs`)** — menggabungkan token USB fisik atau file kunci eksternal (`--keyfile <path>`) dengan kata sandi melalui pra-hashing streaming 64 KiB HMAC-SHA256 sebelum Argon2id.
12. **Enkripsi Aliran Terfragmentasi untuk File Multi-GB (`src/stream.rs`)** — streaming terotentikasi blok 4 MiB dengan penggunaan memori konstan $O(1)$ untuk file raksasa multi-gigabita, perlindungan DPAPI, dan penegakan kebijakan waktu.
13. **Laporan Perbedaan Visual & Statistik Pembawa Stego (`src/diff.rs`)** — mengevaluasi distorsi visual (MSE, PSNR, MAE), distorsi audio (SNR, PSNR), dan pergeseran entropi Shannon $\Delta H$ (`svault compare <original> <stego>`).
14. **Sakelar Dead-Man & Penjaga Penghancuran Diri Maksimal Percobaan (`src/guard.rs`)** — terikat pada buku besar anti-rusak (`.guard`). Jika $K$ upaya gagal berturut-turut tercapai atau tenggat waktu ketidakaktifan berakhir, memicu penghancuran kriptografi 3-tahap (0x00, 0xFF, CSPRNG) dan menghapus file secara permanen.
15. **Generator Kata Sandi Deterministik & CSPRNG (`src/passgen/`)** — Diceware BIP-39 2.048 kata, pembuatan kata sandi tanpa ambiguitas visual (`--exclude-ambiguous`), bita acak murni, dan derivasi benih master (`svault keygen`).
16. **Keluaran JSON Terstruktur Terpadu (`--json`)** — semua perintah mendukung keluaran JSON standar yang dapat dibaca mesin untuk skrip dan otomatisasi CI/CD.
17. **Rotasi Kunci Wadah (`rotate`, `src/rotate.rs`)** — mengenkripsi ulang wadah dan pembawa steganografi secara atomik dengan salt baru, Nonce, dan kredensial tanpa pernah disimpan dalam teks biasa di disk.
18. **Manifes Integritas Kenari Terpisah (`canary`, `src/canary.rs`)** — membuat dan memverifikasi daftar kenari SHA-256 yang ditandatangani HMAC-SHA256 untuk memantau direktori.
19. **Mesin Steganografi MP3 ID3v2 & Bingkai Audio (`src/mp3/`)** — menyembunyikan muatan dalam file MP3 melalui tag ID3v2 PRIV atau celah antar-bingkai dengan penyangkalan yang masuk akal.
20. **Pengikatan Kredensial Perangkat Keras FIDO2 / Windows Hello (`src/hardware_token/`)** — mengikat kunci enkripsi ke kunci USB FIDO2 fisik (YubiKey) atau biometrik TPM Windows Hello melalui CTAP2 PRF dan Argon2id (`svault fido2`).
21. **Enkapsulasi Kunci Hibrida Pasca-Kuantum (`src/pq_kem/`)** — penyegelan asimetris tahan-kuantum lapis ganda menggabungkan X25519 klasik dan NIST FIPS 203 ML-KEM-768 (`svault kem`).
22. **Pembersihan Memori Proaktif (`zeroize`)** — menghapus jadwal kunci sensitif dan buffer teks biasa dari memori dengan 0x00 segera setelah keluar dari cakupan.

</details>

---

## 🏛️ Arsitektur Penyimpanan & Steganografi

<details open>
<summary><b>🏛️ Arsitektur Penyimpanan & Steganografi</b></summary>
<br>

```text
  [ Rahasia Utama ] ──▶ [ ChaCha20-Poly1305 + Padding CSPRNG ] ──┐ (Slot Tersembunyi)
                                                                 │
  [ Muatan Umpan ]  ──▶ [ Enkripsi ChaCha20-Poly1305 ]         ──┴─▶ Wadah SVLT v2 (.svault)
                                                                        ├── Penyimpanan langsung di disk
                                                                        └── Pembawa Steganografi
                                                                              ├── Gambar PNG (.png)
                                                                              ├── Audio WAV (.wav)
                                                                              ├── Gambar BMP (.bmp)
                                                                              └── Audio MP3 (.mp3)
```

</details>

---

## ⚡ Fitur Utama & Jaminan Keamanan

<details open>
<summary><b>⚡ Fitur Utama & Jaminan Keamanan</b></summary>
<br>

- **Argon2id + ChaCha20-Poly1305 AEAD** — salt acak 128-bit, Nonce acak 96-bit, derivasi kunci 256-bit terpisah domain, dan tag autentikasi Poly1305 128-bit.
- **Penjaga Papan Klip Kedaluwarsa Otomatis (`clip`)**:
  - **Panggilan Win32 Asli**: interaksi langsung dengan API papan klip Windows dengan 10 kali percobaan ulang.
  - **Pencegahan Riwayat & Cloud**: menyuntikkan format privasi Windows 10/11 untuk mencegah penyimpanan di riwayat Win+V atau sinkronisasi cloud Microsoft.
  - **Verifikasi Waktu-Konstan**: pencocokan SHA-256 (`constant_time_eq_32`) memastikan papan klip hanya dibersihkan jika masih menyimpan nilai yang dilindungi.
  - **Hitung Mundur Visual**: bilah kemajuan dinamis di terminal (`[████████░░] 12s remaining`), pintasan Enter instan, dan mode senyap (`--silent`).
  - **Integrasi Perintah Langsung**: opsi `--clip` dan `--clip-ttl <detik>` tersedia di `decrypt`, `extract`, `totp code`, dll.
- **Brankas RFC 6238 TOTP 2FA (`totp`)**:
  - **Nol Dependensi Eksternal**: Base32, SHA-1, dan HMAC dengan kelulusan uji 100%.
  - **Perlindungan Perangkat Keras & AEAD**: disimpan dalam wadah `.svault` di bawah perlindungan Argon2id dan DPAPI.
  - **Interoperabilitas Key URI Penuh**: dukungan URI `otpauth://totp/...` standar.
  - **Verifikasi Waktu-Konstan**: perlindungan terhadap serangan waktu dan jendela toleransi ($\pm S$).
- **Auditor Kekuatan Kata Sandi & Entropi (`audit`)**:
  - **Perhitungan Entropi Shannon**: $0.0 \le H \le 8.0$ bit per bita dan ukuran ruang kunci.
  - **Deteksi Kerentanan**: pengulangan, urutan, pola papan ketik, dan kamus leetspeak.
  - **Estimasi Waktu Retas**: pemodelan online (100/detik), offline Argon2id ($10^3$/detik), dan klaster GPU ($10^{10}$/detik).
  - **Steganalisis Pembawa**: uji keseragaman Chi-Square ($\chi^2$) dan validasi struktur.
- **Pembagian Rahasia Shamir ($M$-dari-$N$)**:
  - **Aritmatika Medan Waktu-Konstan**: perkalian tanpa percabangan dan inversi Fermat ($a^{-1} = a^{254}$) di $\text{GF}(256)$.
  - **Integritas Dua Lapis**: digest SHA-256 tersemat dan CRC-32 per bagian.
- **Wadah Penyangkalan yang Masuk Akal dengan Kata Sandi Ganda**:
  - **Dekripsi Mulus**: membuka slot yang sesuai secara otomatis berdasarkan kata sandi yang diberikan.
  - **Slot Tersembunyi yang Tidak Dapat Dibuktikan**: tidak ada header teks biasa; bagian ekor tidak dapat dibedakan dari derau acak (~8.0 bit/bita).
  - **Padding Pengaburan Ukuran (`--padding <bytes>`)**: padding acak CSPRNG untuk mencegah analisis ukuran file.
- **Pengikatan Perangkat Keras / Sesi (`--dpapi`)** — teks tersandi dibatasi pada profil pengguna Windows asli.
- **Pembersihan Memori Proaktif (`zeroize`)** — membersihkan buffer dengan nol saat keluar dari cakupan.
- **Steganografi PNG Tanpa Kehilangan (`embed` / `extract`)** — potongan `svLt` dengan CRC-32 dan dukungan umpan.
- **Steganografi Audio WAV (`embed-wav` / `extract-wav`)**:
  - **Mode Sub-Potongan RIFF (`--mode chunk`)**: metadata `svLt` dengan CRC-32.
  - **Mode LSB PCM 16-bit (`--lsb`)**: mengubah bit terendah tanpa dampak akustik atau perubahan ukuran.
- **Steganografi LSB Piksel BMP 24-bit (`embed-bmp` / `extract-bmp`)**:
  - **Pelestarian Padding Baris**: menjaga keselarasan 4-byte dan memodifikasi saluran R, G, B saja.
  - **Amplop Aman 12-byte**: format `[svLt: 4B][len: 4B LE][payload: NB][crc32: 4B LE]`.
- **Pelindung Koreksi Kesalahan Cauchy Reed-Solomon (`armor` / `dearmor` / `repair`)**:
  - **Kode MDS di $\text{GF}(256)$**: matriks $[I_K; A]$. Kombinasi $K$ bagian utuh merekonstruksi semua data.
  - **CRC-32 per Garis & SHA-256 Global**: pelacakan kerusakan presisi dan autentikasi wadah.
  - **Perbaikan Mandiri Transparan**: pemulihan otomatis di bawah `repair` dan `dearmor`.
- **Pengarsipan Direktori (`pack-dir` / `unpack-dir`)**:
  - **Format Biner `SVAR`**: header 18-byte, hash SHA-256 individu, dan checksum CRC-32.
  - **Pencegahan Zip Slip**: menolak jalur absolut, `..`, dan nama perangkat khusus Windows.
  - **Pertahanan Bom Dekompresi**: batas 8 GiB total dan 4 GiB per file.
- **Estimasi Kapasitas Pembawa (`capacity`)** — perhitungan volume bersih untuk `.bmp`, `.wav`, `.png`, `.mp3`.
- **Inspeksi Header Tanpa Pengetahuan (`inspect`)** — memeriksa versi, salt, dan flag tanpa mendekripsi.
- **Kebijakan Waktu Kunci & Kedaluwarsa (`policy`)**:
  - **Header Kebijakan Terautentikasi (`SVPO`)**: 28-byte kanonik dengan cap waktu dan CRC-32.
  - **Pengikatan AAD pada AEAD**: perubahan tanggal menggagalkan autentikasi Poly1305.
- **File Kunci + Kata Sandi (`keyfile`)** — buffer 64 KiB untuk kunci USB dengan derivasi 256-bit ke Argon2id.
- **Enkripsi Aliran Terfragmentasi (`stream`)** — memori konstan $O(1)$ untuk file puluhan gigabita.
- **Laporan Perbedaan Pembawa Stego (`compare`)** — metrik MSE, PSNR, SNR, dan pergeseran entropi $\Delta H$.
- **Penghancuran Diri & Sakelar Dead-Man (`guard`)** — penghancuran 3 tahap pada kegagalan berulang atau inaktivitas.
- **Generator Kata Sandi Deterministik (`keygen`)** — frasa Diceware BIP-39, kata sandi bebas ambiguitas, dan token.
- **Terminal Interaktif dalam Memori (`repl`)** — manajemen kunci-nilai dalam RAM dengan perlindungan papan klip.
- **Penghancur File Aman (`shred`)** — penimpaan 3-tahap sebelum penghapusan permanen.
- **Biner Statis Tunggal** — tanpa ketergantungan runtime eksternal.

</details>

---

## 🚀 Panduan Cepat dan Alur Kerja CLI

<details open>
<summary><b>🚀 Panduan Cepat dan Alur Kerja CLI (Klik kategori untuk membuka / menutup)</b></summary>
<br>

<details open>
<summary><b>🔐 1. Enkripsi Lapis Ganda & Brankas Umpan Penyangkalan yang Masuk Akal (#1 - #6)</b></summary>
<br>

```bash
# 1. Enkripsi file dengan kata sandi dan pengikatan perangkat keras Windows DPAPI
svault encrypt -i wallet-seed.txt -o wallet.svault -p "your-strong-passphrase" --dpapi

# 2. Enkripsi brankas penyangkalan yang masuk akal yang memuat rahasia asli dan data umpan
svault encrypt -i classified.txt --decoy shopping-list.txt -o deniable.svault \
  -p "primary-secret-pass" --decoy-passphrase "decoy-harmless-pass" --padding 512

# 3. Dekripsi wadah penyangkalan (kata sandi umpan hanya membuka data yang tidak berbahaya)
svault decrypt -i deniable.svault -o revealed.txt -p "decoy-harmless-pass"
# Kata sandi utama memulihkan rahasia asli yang sebenarnya
svault decrypt -i deniable.svault -o restored.txt -p "primary-secret-pass"

# 4. Periksa metadata brankas tanpa mendekripsi (.svault, .png, .wav, atau .bmp)
svault inspect deniable.svault

# 5. Sembunyikan brankas umpan kata sandi ganda langsung di dalam gambar PNG
svault embed -c wallpaper.png -s classified.txt --decoy shopping-list.txt -o wallpaper-stego.png \
  -p "primary-secret-pass" --decoy-passphrase "decoy-harmless-pass"

# 6. Ekstrak rahasia dari gambar PNG (menggunakan kata sandi utama atau kata sandi umpan)
svault extract -c wallpaper-stego.png -o restored-seed.txt -p "primary-secret-pass"
svault extract -c wallpaper-stego.png -o decoy-seed.txt --decoy-passphrase "decoy-harmless-pass"
```

</details>

<details open>
<summary><b>🖼️ 2. Steganografi Media Tanpa Kehilangan: PNG, WAV, BMP, MP3 & Kapasitas (#7 - #13)</b></summary>
<br>

```bash
# 7. Sembunyikan rahasia di dalam file audio WAV (sub-potongan RIFF atau PCM LSB 16-bit)
svault embed-wav -c track.wav -s classified.txt -o track-lsb.wav -p "primary-secret-pass" --lsb

# 8. Ekstrak dan dekripsi rahasia dari file WAV (deteksi otomatis)
svault extract-wav -c track-lsb.wav -o restored-audio.txt -p "primary-secret-pass"

# 9. Perkirakan kapasitas pembawa yang tersedia untuk steganografi (.bmp, .wav, .png, atau .mp3)
svault capacity landscape.bmp
svault capacity track.wav --json
svault capacity song.mp3

# 10. Sembunyikan rahasia di dalam gambar BMP 24-bit melalui steganografi LSB piksel
svault embed-bmp -c landscape.bmp -s classified.txt -o landscape-stego.bmp -p "primary-secret-pass"

# 11. Ekstrak rahasia dari gambar BMP langsung ke papan klip kedaluwarsa otomatis (15 detik)
svault extract-bmp -c landscape-stego.bmp -p "primary-secret-pass" --clip --clip-ttl 15

# 12. Sembunyikan rahasia di dalam file audio MP3 (tag ID3v2 PRIV atau padding antar-bingkai)
svault embed-mp3 -c song.mp3 -s classified.txt -o song-stego.mp3 -p "primary-secret-pass" --mode id3v2
svault embed-mp3 -c song.mp3 -s classified.txt -o song-frame.mp3 -p "primary-secret-pass" --mode frame

# 13. Ekstrak rahasia dari file audio MP3 (pengenalan mode otomatis)
svault extract-mp3 -c song-stego.mp3 -o restored-mp3.txt -p "primary-secret-pass"
```

</details>

<details open>
<summary><b>🧩 3. Penghancuran Aman, Pembagian Rahasia Shamir & Audit Entropi (#12 - #16)</b></summary>
<br>

```bash
# 12. Hancurkan file teks biasa asli secara aman (3 lintasan)
svault shred classified.txt --passes 3

# 13. Bagi kunci pemulihan master menjadi 3-dari-5 bagian Shamir
svault split -s "your-master-seed-or-secret" -m 3 -n 5 -o shares/share

# 14. Gabungkan 3 bagian sembarang untuk merekonstruksi rahasia asli
svault combine shares/share_1.share shares/share_3.share shares/share_5.share -o restored.txt

# 15. Audit kekuatan kata sandi, entropi Shannon, dan estimasi waktu retas
svault audit -p "Correct-Horse-Battery-Staple-2026!"

# 16. Audit gambar pembawa stego atau wadah untuk mendeteksi anomali
svault audit wallpaper-stego.png --json
```

</details>

<details open>
<summary><b>⏱️ 4. Brankas RFC 6238 TOTP 2FA & Penjaga Papan Klip (#17 - #23)</b></summary>
<br>

```bash
# 17. Tambahkan kredensial 2FA TOTP melalui kunci Base32 atau URI otpauth://
svault totp add github --secret "JBSWY3DPEHPK3PXP" --issuer "GitHub" --vault totp.svault -p "vault-pass"
svault totp add --uri "otpauth://totp/Google:alice?secret=JBSWY3DPEHPK3PXP&issuer=Google" --vault totp.svault -p "vault-pass"

# 18. Hasilkan kode OTP 2FA langsung dengan bilah hitung mundur visual (atau --json)
svault totp code github --vault totp.svault -p "vault-pass"
svault totp code github --vault totp.svault -p "vault-pass" --json

# 19. Verifikasi kode OTP dengan jendela toleransi waktu (+/- 1 langkah)
svault totp verify github 123456 --skew 1 --vault totp.svault -p "vault-pass"

# 20. Buat daftar dan ekspor akun 2FA
svault totp list --vault totp.svault -p "vault-pass"
svault totp export github --vault totp.svault -p "vault-pass"

# 21. Salin rahasia ke papan klip dengan kedaluwarsa otomatis 15 detik (atau mode senyap)
svault clip copy "my-super-secret-password" --ttl 15
svault clip copy "my-super-secret-password" --ttl 15 --silent

# 22. Periksa status papan klip dan metadata privasi, atau bersihkan secara manual
svault clip status
svault clip clear

# 23. Dekripsi langsung ke papan klip yang dilindungi tanpa mencetak di terminal atau disk
svault decrypt -i secret.svault -p "vault-pass" --clip --clip-ttl 30
svault totp code github --vault totp.svault -p "vault-pass" --clip --clip-ttl 15
```

</details>

<details open>
<summary><b>🛡️ 5. Pelindung Cauchy Reed-Solomon & Pengarsipan Direktori (#24 - #30)</b></summary>
<br>

```bash
# 24. Lindungi wadah .svault dengan lapis baja ASCII dan garis paritas Cauchy Reed-Solomon (.svault.asc)
svault armor -i secret.svault -o secret.svault.asc -k 4 -m 2

# 25. Ubah kembali file lapis baja ASCII menjadi wadah biner .svault asli
svault dearmor -i secret.svault.asc -o recovered.svault

# 26. Perbaiki file .svault.asc yang rusak menggunakan paritas Cauchy
svault repair -i corrupted.svault.asc -o repaired.svault.asc --json
svault repair -i corrupted.svault.asc -o direct_recovered.svault --binary

# 27. Periksa dan audit integritas garis wadah lapis baja ASCII
svault inspect secret.svault.asc
svault audit secret.svault.asc --json

# 28. Kemas seluruh pohon direktori ke dalam wadah .svault terenkripsi
svault pack-dir -i ./my_project -o project.svault -p "pack-passphrase" --list

# 29. Kemas direktori langsung ke dalam pembawa stego (PNG, WAV, BMP, MP3) atau lapis baja ASCII
svault pack-dir -i ./my_project -o project.png -p "pack-passphrase" --carrier cover.png
svault pack-dir -i ./my_project -o project.svault.asc -p "pack-passphrase" --armor

# 30. Ekstrak direktori, tampilkan daftar manifes, atau pra-validasi digest kriptografi
svault unpack-dir -i project.svault -p "pack-passphrase" --list
svault unpack-dir -i project.svault -p "pack-passphrase" --verify-only
svault unpack-dir -i project.svault -o ./restored_project -p "pack-passphrase" --overwrite
```

</details>

<details open>
<summary><b>⏳ 6. Kebijakan Waktu Kunci, USB Keyfile & Streaming Terfragmentasi (#31 - #42)</b></summary>
<br>

```bash
# 31. Enkripsi dengan kebijakan escrow waktu-kunci (tidak dapat dibuka sebelum tanggal mendatang)
svault encrypt -i escrow.txt -o escrow.svault -p "vault-pass" --not-before "2026-12-31T00:00:00Z" --policy-desc "Year-End Escrow"

# 32. Enkripsi dengan kebijakan kedaluwarsa otomatis (kedaluwarsa dalam 2 jam atau tanggal ISO)
svault encrypt -i token.txt -o token.svault -p "vault-pass" --expires-in 2h --policy-desc "Session Token"
svault encrypt -i doc.txt -o doc.svault -p "vault-pass" --expires-at "2026-10-15"

# 33. Periksa metadata kebijakan tanpa mendekripsi (teks dan JSON)
svault inspect escrow.svault
svault inspect escrow.svault --json

# 34. Uji dekripsi terhadap stempel waktu referensi eksplisit
svault decrypt -i escrow.svault -o restored.txt -p "vault-pass" --at-time "2027-01-01"

# 35. Hasilkan file kunci USB kriptografi (CSPRNG, default 64 bita)
svault keyfile generate -o usb_token.key --bytes 64

# 36. Periksa sidik jari dan entropi Shannon file kunci (teks dan JSON)
svault keyfile inspect usb_token.key
svault keyfile inspect usb_token.key --json
svault keyfile fingerprint usb_token.key

# 37. Enkripsi dan dekripsi dengan 2FA (Kata sandi + File kunci)
svault encrypt -i secret.txt -o sealed.svault -p "master-pass" -k usb_token.key
svault decrypt -i sealed.svault -o restored.txt -p "master-pass" -k usb_token.key

# 38. Enkripsi khusus file kunci tanpa kata sandi
svault encrypt -i token.txt -o hardware.svault -k usb_token.key
svault decrypt -i hardware.svault -o restored.txt -k usb_token.key

# 39. Kemas direktori ke dalam brankas terenkripsi dengan 2FA file kunci
svault pack-dir -i ./confidential -o archive.svault -p "pack-pass" -k usb_token.key
svault unpack-dir -i archive.svault -o ./unpacked -p "pack-pass" -k usb_token.key

# 40. Enkripsi file berukuran multi-gigabita dengan streaming terfragmentasi (blok 4 MiB)
svault stream encrypt -i large_dataset.iso -o large_dataset.svault -p "stream-pass"
svault encrypt -i database.backup -o db.svault -p "stream-pass" --stream --chunk-size 8M

# 41. Dekripsi wadah aliran (mengenali format SVST secara otomatis)
svault decrypt -i large_dataset.svault -o restored.iso -p "stream-pass"
svault stream decrypt -i db.svault -o restored_db.backup -p "stream-pass"

# 42. Periksa metadata wadah aliran tanpa mendekripsi
svault stream inspect large_dataset.svault
svault stream inspect large_dataset.svault --json
```

</details>

<details open>
<summary><b>🚨 7. Laporan Perbedaan Stego, Sakelar Dead-Man & Kata Sandi (#43 - #53)</b></summary>
<br>

```bash
# 43. Bandingkan pembawa asli dengan pembawa stego (PNG, BMP, WAV, atau biner)
svault compare cover.bmp stego.bmp
svault compare cover.png stego.png --json
svault diff original.wav stego.wav --detailed

# 44. Pasang perlindungan brankas dengan penghancuran diri 3 upaya dan sakelar dead-man
svault encrypt -i secret.txt -o guarded.svault -p "vault-pass" --max-attempts 3 --dead-man 7d --guard-companion

# 45. Pasang perlindungan langsung pada pembawa atau wadah yang ada
svault guard arm -t stego.png --max-attempts 3 --companion
svault guard arm -t vault.svault --max-attempts 5 --dead-man 24h

# 46. Periksa status perlindungan dan sisa upaya (teks dan JSON)
svault guard status -t guarded.svault
svault guard status -t guarded.svault --json

# 47. Lapor masuk untuk memperpanjang tenggat waktu dead-man atau mereset penghitung kesalahan
svault guard checkin -t guarded.svault --interval 30d
svault guard reset -t guarded.svault

# 48. Nonaktifkan perlindungan atau picu penghancuran darurat multi-tahap seketika
svault guard disarm -t guarded.svault
svault guard trigger -t guarded.svault --force --passes 3

# 49. Hasilkan frasa pemulihan Diceware BIP-39 6-kata
svault keygen --words 6

# 50. Hasilkan Diceware khusus dengan angka dan huruf kapital
svault keygen --words 4 --separator "." --capitalize --number

# 51. Hasilkan kata sandi 24 karakter dengan filter ambiguitas dan analisis entropi
svault keygen --length 24 --exclude-ambiguous --entropy

# 52. Derivasi kata sandi deterministik dari benih master dan konteks layanan
svault keygen --words 6 --seed "master-recovery-seed" --context "github-token"

# 53. Hasilkan token acak kriptografi 32 bita dan salin ke papan klip
svault keygen --bytes 32 --base64 --clip --clip-ttl 30
svault keygen --bytes 20 --base32 --json
```

</details>

<details open>
<summary><b>💻 8. Rotasi Kunci, Integritas Kenari & Shell Interaktif REPL (#54 - #63)</b></summary>
<br>

```bash
# 54. Rotasi kunci wadah dengan kata sandi baru, salt, dan Nonce segar
svault rotate -i vault.svault -o rotated.svault -p "old-secret" -n "new-secret"

# 55. Rotasi wadah atau pembawa di tempat (in-place) secara atomik
svault rotate -i vault.svault --in-place -p "old-secret" -n "new-secret"
svault rotate -i stego.bmp --in-place -p "old-pass" -n "new-pass"

# 56. Rotasi kredensial pada pembawa stego (PNG, WAV, BMP, atau lapis baja ASCII)
svault rotate -i carrier.png -o rotated.png -p "old-pass" -n "new-pass"
svault rotate -i carrier.asc -o rotated.asc -p "old-pass" -n "new-pass"

# 57. Rotasi dengan mengubah pengikatan perangkat keras DPAPI atau menghapus kebijakan
svault rotate -i vault.svault -o dpapi_vault.svault -p "old-pass" -n "new-pass" --dpapi
svault rotate -i locked.svault -o unlocked.svault -p "old-pass" -n "new-pass" --clear-policy --json

# 58. Inisialisasi manifes kenari integritas terpisah untuk direktori target
svault canary init -d ./vaults
svault canary init -d ./vaults -p "canary-auth-secret" --json

# 59. Verifikasi integritas kenari terhadap perubahan file pada disk
svault canary verify -d ./vaults
svault canary verify -d ./vaults -p "canary-auth-secret" --strict --json

# 60. Mulai shell REPL interaktif brankas kunci-nilai dalam memori
svault repl -v myvault.svault -p "session-pass"

# 61. Jalankan perintah REPL batch secara non-interaktif melalui --exec
svault repl -v myvault.svault -p "session-pass" --exec "set api_key sk_live_xyz --tag prod; set db_pass secret; save"

# 62. Kueri rahasia secara langsung dengan perlindungan papan klip kedaluwarsa otomatis
svault repl -v myvault.svault -p "session-pass" --exec "get api_key --clip --clip-ttl 15"

# 63. Buka REPL dalam mode hanya-baca atau ekspor entri ke JSON
svault repl -v myvault.svault -p "session-pass" --readonly --exec "list" --json
svault repl -v myvault.svault -p "session-pass" --exec "export ./backup.json; exit"
```

</details>

<details open>
<summary><b>🔑 9. Pengikatan Kredensial Kunci FIDO2 / Windows Hello (#64 - #70)</b></summary>
<br>

```bash
# 64. Periksa kemampuan token perangkat keras pada platform host (Windows Hello, WebAuthn API)
svault fido2 status
svault fido2 status --json

# 65. Daftarkan kunci USB FIDO2 atau kredensial Windows Hello
svault fido2 enroll yubikey-5c --type usb --user alice --output ./yubikey.json
svault fido2 enroll hello-tpm --type hello --pin 849201 --json

# 66. Uji asersi autentikator dan verifikasi sidik jari derivasi PRF
svault fido2 test ./yubikey.json
svault fido2 test ./yubikey.json --json

# 67. Enkripsi wadah dengan mengikat kredensial FIDO2 dan kata sandi
svault encrypt -i secret.txt -o sealed.svault --fido2-cred ./yubikey.json -p "master-pass"

# 68. Dekripsi wadah menggunakan kredensial perangkat keras yang terdaftar
svault decrypt -i sealed.svault -o restored.txt --fido2-cred ./yubikey.json -p "master-pass"

# 69. Autentikasi multifaktor 2FA: File kunci + token fisik FIDO2 (tanpa kata sandi)
svault encrypt -i secret.txt -o mfa.svault -k usb_token.key --fido2-cred ./yubikey.json
svault decrypt -i mfa.svault -o restored.txt -k usb_token.key --fido2-cred ./yubikey.json

# 70. Rotasi wadah yang ada untuk menambah atau menghapus ikatan FIDO2
svault rotate -i sealed.svault --in-place -p "old-pass" -n "new-pass" --fido2 --fido2-cred ./yubikey.json
svault rotate -i sealed.svault --in-place -p "new-pass" -n "plain-pass" --no-fido2 --fido2-cred ./yubikey.json
```

</details>

<details open>
<summary><b>⚛️ 10. Enkapsulasi Kunci Hibrida Pasca-Kuantum (X25519 + ML-KEM-768) (#71 - #74)</b></summary>
<br>

```bash
# 71. Hasilkan pasangan kunci hibrida pasca-kuantum (X25519 + ML-KEM-768)
svault kem keygen -p recipient.pub -s recipient.key
svault kem keygen -p recipient.pub -s recipient.key --json

# 72. Segel file rahasia untuk kunci publik penerima (biner atau lapis baja ASCII)
svault kem seal -i classified.txt -o sealed.svault.pq -k recipient.pub
svault kem seal -i classified.txt -o sealed.asc -k recipient.pub --armor --json

# 73. Periksa metadata wadah pasca-kuantum (kunci efemeral, ukuran teks tersandi, CRC-32)
svault kem inspect -i sealed.svault.pq
svault kem inspect -i sealed.asc --json

# 74. Buka dan dekripsi brankas pasca-kuantum menggunakan kunci privat penerima
svault kem open -i sealed.svault.pq -o restored.txt -k recipient.key
svault kem open -i sealed.asc -o restored.txt -k recipient.key --json
```

</details>

</details>

---

## 🔒 Keamanan Memori & Invarian Perlindungan

<details open>
<summary><b>🔒 Keamanan Memori & Invarian Perlindungan</b></summary>
<br>

- **100% Rust Aman & Kriptografi Waktu-Konstan**: Tanpa blok `unsafe` dalam jalur data sensitif; aritmatika medan Galois tanpa cabang untuk mencegah serangan saluran samping waktu.
- **Pembersihan Memori Proaktif**: Jadwal kunci dan buffer teks biasa memicu pembersihan memori terlindung dari optimasi kompilator saat Drop via `zeroize`.
- **Pengikatan Profil Perangkat Keras**: Pembungkusan opsional oleh Windows DPAPI memastikan data terenkripsi tidak dapat dibaca di luar mesin dan sesi pengguna asli.
- **Pertahanan Terhadap Zip Slip & Bom Dekompresi**: Jalur relatif ketat, pemeriksaan drastis, dan batasan alokasi memori mencegah penolakan layanan (DoS).

</details>

---

## 📄 Lisensi dan Atribusi

<details open>
<summary><b>📄 Lisensi dan Atribusi</b></summary>
<br>

Hak Cipta 2026 **GHSFS** ([https://github.com/GHSFS](https://github.com/GHSFS)).

Dilisensikan di bawah **Apache License, Version 2.0** ([`LICENSE`](../../LICENSE)).
Sesuai dengan Bagian 4(d) dari Lisensi Apache 2.0, setiap redistribusi atau karya turunan harus mempertahankan seluruh pemberitahuan atribusi yang terdapat dalam file [`NOTICE`](../../NOTICE).

</details>
