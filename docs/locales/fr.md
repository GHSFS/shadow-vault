<div align="center">

<p align="center">
  <a href="../../README.md">🇺🇸 English</a> · <a href="./ko.md">🇰🇷 한국어</a> · <a href="./zh-CN.md">🇨🇳 中文</a> · <a href="./es.md">🇪🇸 Español</a> · <a href="./hi.md">🇮🇳 हिन्दी</a><br />
  <a href="./ar.md">🇸🇦 العربية</a> · <a href="./pt-BR.md">🇧🇷 Português</a> · <a href="./ru.md">🇷🇺 Русский</a> · <strong>🇫🇷 Français</strong> · <a href="./id.md">🇮🇩 Bahasa Indonesia</a>
</p>

# shadow-vault (`svault`)

> Coffre-fort chiffré à divulgation nulle avec stéganographie et liaison matérielle double couche — dissimulez des fichiers sensibles dans des fichiers PNG/audio ordinaires, scellez-les avec Argon2id + ChaCha20-Poly1305 + Windows DPAPI, ou intégrez des coffres leurres à déni plausible à double mot de passe.

[![Build](https://github.com/GHSFS/shadow-vault/actions/workflows/build.yml/badge.svg)](https://github.com/GHSFS/shadow-vault/actions/workflows/build.yml)
[![Tests](https://github.com/GHSFS/shadow-vault/actions/workflows/test.yml/badge.svg)](https://github.com/GHSFS/shadow-vault/actions/workflows/test.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](../../LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20x64-0078D6)](#démarrage-rapide)

</div>

---

### Aperçu du Projet

`shadow-vault` (`svault.exe`) est un coffre-fort cryptographique et une suite stéganographique autonome en un binaire unique écrit en Rust, conçu pour protéger les données à très haute valeur :

1. **Chiffrement Authentifié Double Couche (`SVLT` v1/v2)** — dérivation de clé **Argon2id** (résistante à la mémoire) + **ChaCha20-Poly1305** AEAD avec liaison matérielle **Windows DPAPI (`CryptProtectData`)**.
2. **Déni Plausible et Coffres Leurres (`src/decoy.rs`)** — dissimulation simultanée d'un secret réel et de données leurres inoffensives ; sous la contrainte, le mot de passe leurre ne révèle que la charge inoffensive.
3. **Stéganographie sans Perte sur Médias Porteurs**:
   - **Images PNG**: insertion d'un bloc auxiliaire `svLt` avant `IEND` avec contrôle CRC-32 IEEE 802.3.
   - **Fichiers WAV**: sous-blocs RIFF et modulation LSB sur les échantillons PCM 16 bits.
   - **Images BMP**: modulation LSB sur les canaux RGB 24 bits avec préservation de l'alignement 4 octets.
   - **Fichiers MP3**: insertion dans les cadres privés ID3v2 `PRIV` ou le remplissage de trame MPEG.
4. **Estimation Universelle de Capacité (`capacity`)** — calcul du volume dissimulable sur `.bmp`, `.wav`, `.png`, `.mp3`.
5. **Partage de Secret de Shamir (`M-sur-N`, `src/shamir.rs`)** — arithmétique en temps constant sur $\text{GF}(256)$ pour diviser un secret en $N$ parts nécessitant $M$ parts pour la reconstruction.
6. **Audit de Robustesse de Mot de Passe et d'Entropie (`src/audit.rs`)** — calcul d'entropie de Shannon et recherche de vulnérabilités.
7. **Coffre TOTP 2FA RFC 6238 (`src/totp.rs`)** — générateur 2FA local et autonome avec protection contre les attaques temporelles.
8. **Protection du Presse-Papiers à Expiration Automatique (`src/clipboard_guard.rs`)** — suppression de l'historique Windows 10/11 et effacement après TTL.
9. **Armure de Correction d'Erreurs Cauchy Reed-Solomon (`src/armor.rs`)** — matrice de Cauchy MDS sur $\text{GF}(256)$ permettant de régénérer toutes les données à partir de $K$ blocs valides sur $K+M$.
10. **Archivage de Répertoire avec Manifeste Sécurisé (`src/archive.rs`)** — protection contre les attaques Zip Slip / Zip Bomb et hachage individuel SHA-256.
11. **Dérivation 2FA avec Fichier Clé (`src/keyfile.rs`)** — liaison avec jeton physique USB et pré-hachage fluide HMAC-SHA256.
12. **Chiffrement Continu par Flux (`src/stream.rs`)** — traitement par blocs de 4 MiB en mémoire constante $O(1)$ pour fichiers volumineux.
13. **Rapport Différentiel Visuel et Statistique (`src/diff.rs`)** — calcul des métriques MSE, PSNR, SNR et déviation d'entropie.
14. **Dispositif Homme-Mort et Auto-Destruction (`src/guard.rs`)** — déchiquetage cryptographique en 3 passes après $K$ tentatives erronées.
15. **Générateur Mnémonique BIP-39 et CSPRNG (`src/passgen/`)** — génération de phrases Diceware de 2 048 mots et jetons cryptographiques.
16. **Sortie Structurée JSON Unifiée (`--json`)** — intégration transparente dans les pipelines d'automatisation CI/CD.
17. **Rotation des Clés (`rotate`)** — renouvellement atomique du sel, du nonce et du mot de passe sans exposition sur disque.
18. **Canari d'Intégrité de Répertoire (`canary`)** — détection d'anomalies et vérification de conformité SHA-256.
19. **Liaison Matérielle FIDO2 et Windows Hello (`src/hardware_token/`)** — prise en charge des clés YubiKey et de la biométrie TPM via CTAP2 PRF.
20. **Encapsulation Hybride Post-Quantique (`src/pq_kem/`)** — alliance de X25519 et du standard NIST FIPS 203 ML-KEM-768.
21. **Nettoyage Mémoire Actif (`zeroize`)** — écrasement immédiat des tampons sensibles en mémoire.

### Démarrage Rapide

```bash
# 1. Chiffrer un fichier avec mot de passe et liaison matérielle DPAPI
svault encrypt -i wallet-seed.txt -o wallet.svault -p "mot-de-passe-robuste" --dpapi

# 2. Créer un coffre à déni plausible avec secret et leurre
svault encrypt -i classified.txt --decoy shopping-list.txt -o deniable.svault \
  -p "pass-principal" --decoy-passphrase "pass-leurre" --padding 512

# 3. Déchiffrer avec le mot de passe leurre
svault decrypt -i deniable.svault -o revealed.txt -p "pass-leurre"

# 4. Inspecter les métadonnées sans déchiffrer
svault inspect deniable.svault

# 5. Dissimuler un coffre dans une image PNG
svault embed -c wallpaper.png -s classified.txt --decoy shopping-list.txt -o wallpaper-stego.png \
  -p "pass-principal" --decoy-passphrase "pass-leurre"

# 6. Extraire le secret réel depuis l'image PNG
svault extract -c wallpaper-stego.png -o restored-seed.txt -p "pass-principal"
```

### Licence et Attribution

Copyright 2026 **GHSFS** ([https://github.com/GHSFS](https://github.com/GHSFS)).

Distribué sous licence **Apache 2.0** ([LICENSE](../../LICENSE)). Veuillez vous référer au fichier [NOTICE](../../NOTICE) pour les mentions d'attribution obligatoires.
