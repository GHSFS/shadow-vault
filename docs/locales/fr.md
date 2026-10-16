<div align="center">

<p align="center">
  <a href="../../README.md">🇺🇸 English</a> · <a href="./ko.md">🇰🇷 한국어</a> · <a href="./zh-CN.md">🇨🇳 中文</a> · <a href="./es.md">🇪🇸 Español</a> · <a href="./hi.md">🇮🇳 हिन्दी</a><br />
  <a href="./ar.md">🇸🇦 العربية</a> · <a href="./pt-BR.md">🇧🇷 Português</a> · <a href="./ru.md">🇷🇺 Русский</a> · <strong>🇫🇷 Français</strong> · <a href="./id.md">🇮🇩 Bahasa Indonesia</a>
</p>

# shadow-vault (`svault`)

> Stéganographie Zero-Trust et coffre-fort chiffré à double couche lié au matériel — dissimulez vos fichiers sensibles dans des supports PNG/audio ordinaires, scellez-les avec Argon2id + ChaCha20-Poly1305 + Windows DPAPI, ou intégrez des leurres à déni plausible par double mot de passe.

[![Build](https://github.com/GHSFS/shadow-vault/actions/workflows/build.yml/badge.svg)](https://github.com/GHSFS/shadow-vault/actions/workflows/build.yml)
[![Tests](https://github.com/GHSFS/shadow-vault/actions/workflows/test.yml/badge.svg)](https://github.com/GHSFS/shadow-vault/actions/workflows/test.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](../../LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20x64-0078D6)](#-démarrage-rapide-et-flux-cli)

</div>

---

## 🛡️ Présentation et fonctionnalités clés

<details open>
<summary><b>🛡️ Présentation et fonctionnalités clés</b></summary>
<br>

`shadow-vault` (`svault.exe`) est une boîte à outils cryptographique et stéganographique binaire unique écrite en Rust sans aucune dépendance externe, conçue pour les opérateurs exigeant une protection de niveau militaire pour leurs fichiers de haute valeur (phrases de récupération, clés privées, identifiants, notes de recherche confidentielles) :

1. **Chiffrement authentifié à double couche (`SVLT` v1/v2)** — associe la dérivation de clé avec durcissement mémoire **Argon2id** + **ChaCha20-Poly1305** AEAD à une liaison matérielle et de session utilisateur optionnelle **Windows DPAPI (`CryptProtectData`)**. Même si un attaquant dérobe physiquement le fichier `.svault` et la phrase secrète, un coffre lié à DPAPI ne peut être déchiffré en dehors de votre session utilisateur Windows d'origine.
2. **Déni plausible et coffres leurres (`src/decoy.rs`)** — intègre à la fois le secret principal (déverrouillé par le mot de passe maître) et une charge utile leurre inoffensive (déverrouillée par le mot de passe leurre) au sein d'un conteneur unique. Sous la contrainte, fournir le mot de passe leurre ne libère que les données factices, tandis que l'emplacement principal dissimulé demeure statistiquement indiscernable d'un bruit aléatoire uniforme (remplissage CSPRNG et texte chiffré ChaCha20-Poly1305).
3. **Stéganographie multimédia sans perte** — dissimule les conteneurs chiffrés au sein de supports multimédias ordinaires :
   - **Images PNG (`embed` / `extract`)** : injecte un bloc auxiliaire privé `svLt` avant `IEND` avec des sommes de contrôle IEEE 802.3 CRC-32 valides (supporte l'intégration directe de coffres leurres).
   - **Fichiers audio WAV (`embed-wav` / `extract-wav`)** : prend en charge les sous-blocs RIFF/WAVE (`--mode chunk`) et la substitution du bit le moins significatif (LSB) sur des échantillons audio PCM 16 bits (`--lsb`) avec validation CRC-32.
   - **Images BMP (`src/bmp.rs`)** : module le LSB sur les canaux de pixels RGB non compressés 24 bits en préservant strictement l'alignement sur 4 octets et en intégrant une enveloppe de 12 octets infalsifiable (`svLt`, longueur, charge utile, CRC-32).
   - **Fichiers audio MP3 (`src/mp3/`)** : dissimule la charge utile dans les trames privées ID3v2.3/ID3v2.4 (`PRIV`) ou dans les espaces inter-trames MPEG Audio Layer III avec validation de synchronisation, préservation des métadonnées (TIT2, TPE1) et estimation de la capacité.
4. **Estimation universelle de capacité du support (`capacity`)** — calcule avec précision la taille totale, la capacité utile en octets et la surcharge stéganographique sur les supports `.bmp`, `.wav`, `.png` et `.mp3` (`svault capacity <carrier> [--json]`).
5. **Partage de secret de Shamir (`M-of-N`, `src/shamir.rs`)** — arithmétique de corps fini $\text{GF}(256)$ en temps constant sans branchement conditionnel. Divise les clés de récupération, phrases secrètes ou conteneurs en $N$ parts, nécessitant $M$ parts quelconques pour reconstruire le secret (`svault split` / `svault combine`). Prend en charge le texte blindé ASCII, les chaînes compactes et JSON.
6. **Auditeur de robustesse de mot de passe et d'entropie (`src/audit.rs`)** — calcule l'entropie de Shannon (bits/octet), la diversité des caractères et détecte les motifs vulnérables (répétitions, séquences, parcours clavier, leetspeak). Audite les blocs PNG, flux WAV RIFF/LSB, LSB de pixels BMP et conteneurs `.svault` (`svault audit <target>` / `svault audit -p <passphrase>`).
7. **Coffre 2FA TOTP RFC 6238 (`src/totp.rs`)** — gestionnaire d'authentification à deux facteurs local chiffré sans dépendance externe, scellé dans des conteneurs `.svault`. Inclut Base32 (RFC 4648), RFC 3174 SHA-1, RFC 2104 HMAC (SHA-1/256/512), parseur `otpauth://totp/...`, vérification en temps constant et compte à rebours dynamique dans le terminal (`svault totp add`, `svault totp code`, `svault totp list`, `svault totp verify`).
8. **Protection du presse-papiers avec expiration automatique (`src/clipboard_guard.rs`)** — copie en toute sécurité les identifiants dans le presse-papiers Windows et les efface après un TTL configurable (ex. `--clip-ttl 15`). Injecte les métadonnées de confidentialité Windows 10/11 pour empêcher l'historique (Win + V) et la synchronisation cloud, avec vérification d'empreinte SHA-256 en temps constant (`constant_time_eq_32`).
9. **Armure de correction d'erreurs Cauchy Reed-Solomon (`src/armor.rs`)** — ajoute des bandes de parité et un export/import/réparation ASCII blindé `.svault.asc` pour survivre à la dégradation des bits ou aux coupures de transmission. Utilise une matrice de Cauchy $[I_K; A]$ sur $\text{GF}(256)$ avec propriétés MDS : $K$ bandes saines quelconques parmi $K+M$ suffisent à régénérer toutes les données (`svault repair`).
10. **Archivage de répertoires et manifeste multi-fichiers (`src/archive.rs`)** — archive des arborescences complètes avec normalisation des chemins relatifs, prévention Zip Slip, défense contre les bombes de décompression, manifestes SHA-256 par fichier et préservation des permissions sous un conteneur `SVLT` unique (`svault pack-dir` / `svault unpack-dir`).
11. **Dérivation à deux facteurs Keyfile + Mot de passe (`src/keyfile.rs`)** — combine un jeton USB physique ou fichier clé (`--keyfile <path>`) avec un mot de passe via un pré-hachage en flux de 64 KiB HMAC-SHA256 avant Argon2id.
12. **Chiffrement par flux fragmenté pour fichiers volumineux (`src/stream.rs`)** — streaming authentifié par blocs de 4 MiB avec une utilisation mémoire constante $O(1)$ pour des fichiers géants de plusieurs gigaoctets, protection DPAPI et politiques temporelles.
13. **Rapport différentiel visuel et statistique du support (`src/diff.rs`)** — évalue la distorsion visuelle (MSE, PSNR, MAE), la distorsion audio (SNR, PSNR) et l'écart d'entropie de Shannon $\Delta H$ (`svault compare <original> <stego>`).
14. **Dispositif d'homme mort et autodestruction sur tentatives (`src/guard.rs`)** — lié à un registre inviolable (`.guard`). En cas de $K$ tentatives erronées consécutives ou d'expiration du délai d'inactivité, exécute un broyage cryptographique en 3 passes (0x00, 0xFF, CSPRNG) et détruit définitivement le fichier.
15. **Générateur de mots de passe déterministe et CSPRNG (`src/passgen/`)** — phrases Diceware BIP-39 de 2 048 mots, mots de passe sans ambiguïté visuelle (`--exclude-ambiguous`), octets aléatoires et dérivation déterministe (`svault keygen`).
16. **Sortie JSON structurée unifiée (`--json`)** — toutes les commandes prennent en charge des réponses JSON standardisées pour l'automatisation et les pipelines CI/CD.
17. **Rotation de clés de conteneur (`rotate`, `src/rotate.rs`)** — rechiffre de manière atomique les conteneurs et supports avec un nouveau sel, Nonce et identifiants sans écriture en clair sur disque.
18. **Manifeste d'intégrité canari détaché (`canary`, `src/canary.rs`)** — crée et vérifie des listes canari SHA-256 signées avec HMAC-SHA256 pour surveiller les répertoires.
19. **Moteur stéganographique MP3 ID3v2 et trames audio (`src/mp3/`)** — dissimule des données dans les fichiers MP3 avec détection transparente et déni plausible.
20. **Liaison matérielle FIDO2 / Windows Hello (`src/hardware_token/`)** — lie les clés de chiffrement à des clés physiques FIDO2 USB ou à la biométrie TPM Windows Hello via CTAP2 PRF et Argon2id (`svault fido2`).
21. **Encapsulation de clé hybride post-quantique (`src/pq_kem/`)** — scellement asymétrique à double couche combinant X25519 classique et NIST FIPS 203 ML-KEM-768 (`svault kem`).
22. **Mise à zéro proactive de la mémoire (`zeroize`)** — efface les clés et mémoires tampons sensibles avec 0x00 dès la fin de leur utilisation.

</details>

---

## 🏛️ Architecture de stockage et de stéganographie

<details open>
<summary><b>🏛️ Architecture de stockage et de stéganographie</b></summary>
<br>

```text
  [ Secret Principal ] ──▶ [ ChaCha20-Poly1305 + Remplissage CSPRNG ] ──┐ (Emplacement Caché)
                                                                        │
  [ Charge Leurre ]    ──▶ [ Chiffrement ChaCha20-Poly1305 ]          ──┴─▶ Conteneur SVLT v2 (.svault)
                                                                              ├── Stockage direct sur disque
                                                                              └── Support Stéganographique
                                                                                    ├── Image PNG (.png)
                                                                                    ├── Audio WAV (.wav)
                                                                                    ├── Image BMP (.bmp)
                                                                                    └── Audio MP3 (.mp3)
```

</details>

---

## ⚡ Fonctionnalités clés et garanties de sécurité

<details open>
<summary><b>⚡ Fonctionnalités clés et garanties de sécurité</b></summary>
<br>

- **Argon2id + ChaCha20-Poly1305 AEAD** — sel aléatoire de 128 bits, Nonce aléatoire de 96 bits, dérivation de clé 256 bits avec séparation de domaines et étiquette d'authentification Poly1305 de 128 bits.
- **Protection du presse-papiers avec expiration automatique (`clip`)** :
  - **Appels Win32 natifs** : pilotage direct des API de presse-papiers Windows avec 10 tentatives automatiques.
  - **Blocage de l'historique et du cloud** : injection des métadonnées de confidentialité Windows 10/11 pour empêcher l'enregistrement dans Win+V et la synchronisation cloud Microsoft.
  - **Vérification en temps constant** : comparaison SHA-256 (`constant_time_eq_32`) garantissant que le presse-papiers n'est vidé que s'il contient toujours la valeur protégée.
  - **Compte à rebours dynamique** : barre de progression dans la console (`[████████░░] 12s remaining`), raccourci Enter pour vidage immédiat et mode silencieux (`--silent`).
  - **Intégration directe** : options `--clip` et `--clip-ttl <sec>` disponibles sur `decrypt`, `extract`, `totp code`, etc.
- **Coffre 2FA TOTP RFC 6238 (`totp`)** :
  - **Zéro dépendance externe** : Base32, SHA-1 et HMAC avec 100% de tests réussis.
  - **Protection par matériel et AEAD** : conteneurs `.svault` protégés par Argon2id et DPAPI.
  - **Interopérabilité Key URI** : prise en charge des URI `otpauth://totp/...`.
  - **Vérification en temps constant** : protection contre les attaques temporelles et fenêtre de tolérance ($\pm S$).
- **Auditeur de robustesse de mot de passe et d'entropie (`audit`)** :
  - **Calcul d'entropie de Shannon** : $0.0 \le H \le 8.0$ bits par octet et espace de clés.
  - **Détection des faiblesses** : répétitions, suites, motifs clavier et correspondances dictionnaires.
  - **Estimation du temps de déchiffrement** : modèles en ligne (100/s), Argon2id hors ligne ($10^3$/s) et grappes GPU ($10^{10}$/s).
  - **Stéganalyse des supports** : tests de conformité et test d'uniformité Chi-carré ($\chi^2$).
- **Partage de secret de Shamir ($M$-sur-$N$)** :
  - **Arithmétique sans branchement** : multiplication sans saut et inversion de Fermat ($a^{-1} = a^{254}$) dans $\text{GF}(256)$.
  - **Intégrité double couche** : empreinte SHA-256 intégrée et CRC-32 par part.
- **Conteneurs à déni plausible par double mot de passe** :
  - **Déchiffrement transparent** : ouvre automatiquement l'emplacement correspondant au mot de passe saisi.
  - **Emplacement caché indémontrable** : aucun en-tête apparent ; la zone finale correspond à un bruit blanc (~8.0 bits/octet).
  - **Dissimulation de taille (`--padding <bytes>`)** : remplissage aléatoire CSPRNG.
- **Liaison au matériel / à la session (`--dpapi`)** — texte chiffré verrouillé sur le profil utilisateur Windows d'origine.
- **Mise à zéro proactive de la mémoire (`zeroize`)** — effacement immédiat des zones tampons à la destruction des objets.
- **Stéganographie PNG sans perte (`embed` / `extract`)** — bloc `svLt` avec CRC-32 et support des leurres.
- **Stéganographie audio WAV (`embed-wav` / `extract-wav`)** :
  - **Mode sous-bloc RIFF (`--mode chunk`)** : métadonnées `svLt` avec CRC-32.
  - **Mode LSB PCM 16 bits (`--lsb`)** : altération du bit le moins significatif sans impact sonore perceptible.
- **Stéganographie LSB sur pixels BMP 24 bits (`embed-bmp` / `extract-bmp`)** :
  - **Respect de l'alignement de ligne** : navigation sur le pas de 4 octets et modification des canaux R, G, B uniquement.
  - **Enveloppe sécurisée de 12 octets** : format `[svLt: 4B][len: 4B LE][payload: NB][crc32: 4B LE]`.
- **Armure de correction d'erreurs Cauchy Reed-Solomon (`armor` / `dearmor` / `repair`)** :
  - **Code MDS sur $\text{GF}(256)$** : matrice $[I_K; A]$. Toute combinaison de $K$ bandes intactes reconstruit tout.
  - **CRC-32 par bande et SHA-256 global** : localisation d'erreur et authentification intégrale du conteneur.
  - **Autoréparation transparente** : régénération automatique sous `repair` et `dearmor`.
- **Archivage de répertoires (`pack-dir` / `unpack-dir`)** :
  - **Format binaire `SVAR`** : en-tête 18 octets, hachages SHA-256 individuels et somme CRC-32.
  - **Prévention Zip Slip** : rejet des chemins absolus, des `..` et des noms réservés Windows.
  - **Défense contre les bombes de décompression** : plafonds de 8 Gio au total et 4 Gio par fichier.
- **Estimation de capacité de support (`capacity`)** — calcul du volume net utile pour `.bmp`, `.wav`, `.png`, `.mp3`.
- **Inspection d'en-tête sans déchiffrement (`inspect`)** — lecture de version, sel et drapeaux sans dévoiler le secret.
- **Politiques temporelles de verrouillage et d'expiration (`policy`)** :
  - **En-tête de politique authentifié (`SVPO`)** : 28 octets canoniques avec horodatage et CRC-32.
  - **Liaison AAD sous AEAD** : toute modification des dates invalide Poly1305.
- **Fichier clé + Mot de passe (`keyfile`)** — tampon de 64 KiB pour clés USB avec dérivation de 256 bits vers Argon2id.
- **Chiffrement par flux fragmenté (`stream`)** — mémoire constante $O(1)$ pour fichiers de plusieurs gigaoctets.
- **Rapport différentiel de support (`compare`)** — métriques MSE, PSNR, SNR et dérive d'entropie $\Delta H$.
- **Autodestruction et dispositif d'homme mort (`guard`)** — broyage en 3 passes en cas d'échecs répétés ou d'inactivité.
- **Générateur de mots de passe déterministe (`keygen`)** — phrases Diceware BIP-39, mots de passe sans ambiguïté et jetons.
- **Terminal interactif en mémoire (`repl`)** — gestion clé-valeur dans la RAM avec protection du presse-papiers.
- **Destructeur de fichiers sécurisé (`shred`)** — écrasement en 3 étapes avant suppression.
- **Binaire statique unique** — aucune dépendance d'exécution externe.

</details>

---

## 🚀 Démarrage rapide et flux CLI

<details open>
<summary><b>🚀 Démarrage rapide et flux CLI (Cliquez sur une catégorie pour déplier / replier)</b></summary>
<br>

<details open>
<summary><b>🔐 1. Chiffrement double couche et leurres à déni plausible (#1 - #6)</b></summary>
<br>

```bash
# 1. Chiffrer un fichier avec mot de passe et liaison matérielle Windows DPAPI
svault encrypt -i wallet-seed.txt -o wallet.svault -p "your-strong-passphrase" --dpapi

# 2. Chiffrer un coffre à déni plausible contenant secret réel et leurre factice
svault encrypt -i classified.txt --decoy shopping-list.txt -o deniable.svault \
  -p "primary-secret-pass" --decoy-passphrase "decoy-harmless-pass" --padding 512

# 3. Déchiffrer un conteneur à déni (le mot de passe leurre ne révèle que les données inoffensives)
svault decrypt -i deniable.svault -o revealed.txt -p "decoy-harmless-pass"
# Le mot de passe principal restaure le secret réel d'origine
svault decrypt -i deniable.svault -o restored.txt -p "primary-secret-pass"

# 4. Inspecter les métadonnées sans déchiffrer (.svault, .png, .wav ou .bmp)
svault inspect deniable.svault

# 5. Dissimuler un coffre leurre à double mot de passe directement dans une image PNG
svault embed -c wallpaper.png -s classified.txt --decoy shopping-list.txt -o wallpaper-stego.png \
  -p "primary-secret-pass" --decoy-passphrase "decoy-harmless-pass"

# 6. Extraire le secret depuis l'image PNG (avec le mot de passe maître ou leurre)
svault extract -c wallpaper-stego.png -o restored-seed.txt -p "primary-secret-pass"
svault extract -c wallpaper-stego.png -o decoy-seed.txt --decoy-passphrase "decoy-harmless-pass"
```

</details>

<details open>
<summary><b>🖼️ 2. Stéganographie multimédia sans perte : PNG, WAV, BMP, MP3 et capacité (#7 - #13)</b></summary>
<br>

```bash
# 7. Dissimuler un secret dans un fichier audio WAV (sous-bloc RIFF ou LSB 16 bits)
svault embed-wav -c track.wav -s classified.txt -o track-lsb.wav -p "primary-secret-pass" --lsb

# 8. Extraire et déchiffrer le secret d'un fichier WAV (détection automatique)
svault extract-wav -c track-lsb.wav -o restored-audio.txt -p "primary-secret-pass"

# 9. Estimer la capacité utile du support pour la stéganographie (.bmp, .wav, .png ou .mp3)
svault capacity landscape.bmp
svault capacity track.wav --json
svault capacity song.mp3

# 10. Dissimuler un secret dans une image BMP 24 bits par LSB sur les pixels
svault embed-bmp -c landscape.bmp -s classified.txt -o landscape-stego.bmp -p "primary-secret-pass"

# 11. Extraire le secret d'une image BMP directement vers le presse-papiers temporaire (15s)
svault extract-bmp -c landscape-stego.bmp -p "primary-secret-pass" --clip --clip-ttl 15

# 12. Dissimuler un secret dans un fichier audio MP3 (tag ID3v2 PRIV ou inter-trames)
svault embed-mp3 -c song.mp3 -s classified.txt -o song-stego.mp3 -p "primary-secret-pass" --mode id3v2
svault embed-mp3 -c song.mp3 -s classified.txt -o song-frame.mp3 -p "primary-secret-pass" --mode frame

# 13. Extraire le secret d'un fichier MP3 (reconnaissance automatique du mode)
svault extract-mp3 -c song-stego.mp3 -o restored-mp3.txt -p "primary-secret-pass"
```

</details>

<details open>
<summary><b>🧩 3. Destruction sécurisée, partage de Shamir et audit d'entropie (#12 - #16)</b></summary>
<br>

```bash
# 12. Détruire définitivement le fichier texte brut d'origine (en 3 passes)
svault shred classified.txt --passes 3

# 13. Diviser une clé maîtresse de récupération en 3-sur-5 parts de Shamir
svault split -s "your-master-seed-or-secret" -m 3 -n 5 -o shares/share

# 14. Combiner 3 parts quelconques pour reconstituer le secret d'origine
svault combine shares/share_1.share shares/share_3.share shares/share_5.share -o restored.txt

# 15. Auditer la robustesse d'un mot de passe, l'entropie de Shannon et le temps de déchiffrement
svault audit -p "Correct-Horse-Battery-Staple-2026!"

# 16. Auditer une image de support ou un conteneur pour détecter d'éventuelles anomalies
svault audit wallpaper-stego.png --json
```

</details>

<details open>
<summary><b>⏱️ 4. Coffre 2FA TOTP RFC 6238 et protection du presse-papiers (#17 - #23)</b></summary>
<br>

```bash
# 17. Ajouter un compte 2FA TOTP par clé Base32 ou URI otpauth://
svault totp add github --secret "JBSWY3DPEHPK3PXP" --issuer "GitHub" --vault totp.svault -p "vault-pass"
svault totp add --uri "otpauth://totp/Google:alice?secret=JBSWY3DPEHPK3PXP&issuer=Google" --vault totp.svault -p "vault-pass"

# 18. Générer le code OTP 2FA en direct avec jauge de compte à rebours (ou --json)
svault totp code github --vault totp.svault -p "vault-pass"
svault totp code github --vault totp.svault -p "vault-pass" --json

# 19. Vérifier un code OTP avec tolérance temporelle (+/- 1 intervalle)
svault totp verify github 123456 --skew 1 --vault totp.svault -p "vault-pass"

# 20. Lister et exporter les comptes 2FA
svault totp list --vault totp.svault -p "vault-pass"
svault totp export github --vault totp.svault -p "vault-pass"

# 21. Copier le secret dans le presse-papiers avec effacement automatique après 15s (ou silencieux)
svault clip copy "my-super-secret-password" --ttl 15
svault clip copy "my-super-secret-password" --ttl 15 --silent

# 22. Vérifier l'état du presse-papiers et les métadonnées de confidentialité, ou vider
svault clip status
svault clip clear

# 23. Déchiffrer directement vers le presse-papiers sans affichage console ni écriture disque
svault decrypt -i secret.svault -p "vault-pass" --clip --clip-ttl 30
svault totp code github --vault totp.svault -p "vault-pass" --clip --clip-ttl 15
```

</details>

<details open>
<summary><b>🛡️ 5. Armure Cauchy Reed-Solomon et archivage de dossiers (#24 - #30)</b></summary>
<br>

```bash
# 24. Protéger un conteneur .svault avec armure ASCII et parité Cauchy Reed-Solomon (.svault.asc)
svault armor -i secret.svault -o secret.svault.asc -k 4 -m 2

# 25. Reconvertir un fichier blindé ASCII vers le conteneur binaire .svault d'origine
svault dearmor -i secret.svault.asc -o recovered.svault

# 26. Réparer un fichier .svault.asc corrompu grâce à la parité de Cauchy
svault repair -i corrupted.svault.asc -o repaired.svault.asc --json
svault repair -i corrupted.svault.asc -o direct_recovered.svault --binary

# 27. Inspecter et auditer l'intégrité des bandes d'un conteneur blindé ASCII
svault inspect secret.svault.asc
svault audit secret.svault.asc --json

# 28. Archiver une arborescence complète dans un conteneur chiffré .svault
svault pack-dir -i ./my_project -o project.svault -p "pack-passphrase" --list

# 29. Archiver directement dans un support stéganographique (PNG, WAV, BMP, MP3) ou armure ASCII
svault pack-dir -i ./my_project -o project.png -p "pack-passphrase" --carrier cover.png
svault pack-dir -i ./my_project -o project.svault.asc -p "pack-passphrase" --armor

# 30. Désarchiver le dossier, afficher la liste ou pré-valider les empreintes
svault unpack-dir -i project.svault -p "pack-passphrase" --list
svault unpack-dir -i project.svault -p "pack-passphrase" --verify-only
svault unpack-dir -i project.svault -o ./restored_project -p "pack-passphrase" --overwrite
```

</details>

<details open>
<summary><b>⏳ 6. Politiques temporelles, clés USB Keyfile et streaming fragmenté (#31 - #42)</b></summary>
<br>

```bash
# 31. Chiffrer avec politique de séquestre temporel (inaccessible avant la date future)
svault encrypt -i escrow.txt -o escrow.svault -p "vault-pass" --not-before "2026-12-31T00:00:00Z" --policy-desc "Year-End Escrow"

# 32. Chiffrer avec politique d'auto-expiration (expire après 2 heures ou à une date ISO)
svault encrypt -i token.txt -o token.svault -p "vault-pass" --expires-in 2h --policy-desc "Session Token"
svault encrypt -i doc.txt -o doc.svault -p "vault-pass" --expires-at "2026-10-15"

# 33. Inspecter les métadonnées de politique sans déchiffrer (texte et JSON)
svault inspect escrow.svault
svault inspect escrow.svault --json

# 34. Tester le déchiffrement par rapport à une date de référence explicite
svault decrypt -i escrow.svault -o restored.txt -p "vault-pass" --at-time "2027-01-01"

# 35. Générer un fichier clé cryptographique USB (CSPRNG, 64 octets par défaut)
svault keyfile generate -o usb_token.key --bytes 64

# 36. Inspecter l'empreinte et l'entropie de Shannon du fichier clé (texte et JSON)
svault keyfile inspect usb_token.key
svault keyfile inspect usb_token.key --json
svault keyfile fingerprint usb_token.key

# 37. Chiffrer et déchiffrer avec double facteur 2FA (Mot de passe + Fichier clé)
svault encrypt -i secret.txt -o sealed.svault -p "master-pass" -k usb_token.key
svault decrypt -i sealed.svault -o restored.txt -p "master-pass" -k usb_token.key

# 38. Chiffrement exclusif par fichier clé sans mot de passe
svault encrypt -i token.txt -o hardware.svault -k usb_token.key
svault decrypt -i hardware.svault -o restored.txt -k usb_token.key

# 39. Archiver un dossier dans un coffre chiffré avec 2FA par fichier clé
svault pack-dir -i ./confidential -o archive.svault -p "pack-pass" -k usb_token.key
svault unpack-dir -i archive.svault -o ./unpacked -p "pack-pass" -k usb_token.key

# 40. Chiffrer des fichiers de plusieurs gigaoctets par flux fragmenté (blocs de 4 MiB)
svault stream encrypt -i large_dataset.iso -o large_dataset.svault -p "stream-pass"
svault encrypt -i database.backup -o db.svault -p "stream-pass" --stream --chunk-size 8M

# 41. Déchiffrer un conteneur en flux (reconnaissance du format SVST)
svault decrypt -i large_dataset.svault -o restored.iso -p "stream-pass"
svault stream decrypt -i db.svault -o restored_db.backup -p "stream-pass"

# 42. Inspecter les métadonnées d'un conteneur en flux sans déchiffrer
svault stream inspect large_dataset.svault
svault stream inspect large_dataset.svault --json
```

</details>

<details open>
<summary><b>🚨 7. Rapports de différences, garde d'autodestruction et mots de passe (#43 - #53)</b></summary>
<br>

```bash
# 43. Comparer le support original et le support stéganographique (PNG, BMP, WAV ou binaire)
svault compare cover.bmp stego.bmp
svault compare cover.png stego.png --json
svault diff original.wav stego.wav --detailed

# 44. Armer un coffre avec autodestruction à 3 tentatives et dispositif d'homme mort
svault encrypt -i secret.txt -o guarded.svault -p "vault-pass" --max-attempts 3 --dead-man 7d --guard-companion

# 45. Armer directement un support ou un conteneur existant
svault guard arm -t stego.png --max-attempts 3 --companion
svault guard arm -t vault.svault --max-attempts 5 --dead-man 24h

# 46. Inspecter l'état de la garde et les tentatives restantes (texte et JSON)
svault guard status -t guarded.svault
svault guard status -t guarded.svault --json

# 47. Pointer pour renouveler le délai d'homme mort ou réinitialiser le compteur d'échecs
svault guard checkin -t guarded.svault --interval 30d
svault guard reset -t guarded.svault

# 48. Désarmer la garde ou déclencher le broyage d'urgence immédiat
svault guard disarm -t guarded.svault
svault guard trigger -t guarded.svault --force --passes 3

# 49. Générer une phrase de récupération Diceware BIP-39 de 6 mots
svault keygen --words 6

# 50. Générer un Diceware personnalisé avec chiffres et majuscules
svault keygen --words 4 --separator "." --capitalize --number

# 51. Générer un mot de passe de 24 caractères avec filtre d'ambiguïté et analyse d'entropie
svault keygen --length 24 --exclude-ambiguous --entropy

# 52. Dérivation déterministe de mot de passe à partir d'une graine et d'un contexte de service
svault keygen --words 6 --seed "master-recovery-seed" --context "github-token"

# 53. Générer un jeton cryptographique aléatoire de 32 octets et le copier dans le presse-papiers
svault keygen --bytes 32 --base64 --clip --clip-ttl 30
svault keygen --bytes 20 --base32 --json
```

</details>

<details open>
<summary><b>💻 8. Rotation de clés, intégrité canari et terminal interactif REPL (#54 - #63)</b></summary>
<br>

```bash
# 54. Renouveler les clés d'un conteneur avec un nouveau mot de passe, sel et Nonce
svault rotate -i vault.svault -o rotated.svault -p "old-secret" -n "new-secret"

# 55. Renouveler atomiquement un conteneur ou un support sur place
svault rotate -i vault.svault --in-place -p "old-secret" -n "new-secret"
svault rotate -i stego.bmp --in-place -p "old-pass" -n "new-pass"

# 56. Renouveler les identifiants d'un support stéganographique (PNG, WAV, BMP ou armure ASCII)
svault rotate -i carrier.png -o rotated.png -p "old-pass" -n "new-pass"
svault rotate -i carrier.asc -o rotated.asc -p "old-pass" -n "new-pass"

# 57. Renouveler en modifiant la liaison matérielle DPAPI ou en effaçant les politiques
svault rotate -i vault.svault -o dpapi_vault.svault -p "old-pass" -n "new-pass" --dpapi
svault rotate -i locked.svault -o unlocked.svault -p "old-pass" -n "new-pass" --clear-policy --json

# 58. Initialiser un manifeste canari d'intégrité détaché pour le dossier cible
svault canary init -d ./vaults
svault canary init -d ./vaults -p "canary-auth-secret" --json

# 59. Vérifier l'intégrité canari contre les altérations de fichiers sur disque
svault canary verify -d ./vaults
svault canary verify -d ./vaults -p "canary-auth-secret" --strict --json

# 60. Lancer la console REPL interactive de gestion clé-valeur en mémoire
svault repl -v myvault.svault -p "session-pass"

# 61. Exécuter des commandes REPL en lot de manière non interactive avec --exec
svault repl -v myvault.svault -p "session-pass" --exec "set api_key sk_live_xyz --tag prod; set db_pass secret; save"

# 62. Consulter un secret directement sous la protection du presse-papiers temporaire
svault repl -v myvault.svault -p "session-pass" --exec "get api_key --clip --clip-ttl 15"

# 63. Ouvrir REPL en lecture seule ou exporter les entrées en JSON
svault repl -v myvault.svault -p "session-pass" --readonly --exec "list" --json
svault repl -v myvault.svault -p "session-pass" --exec "export ./backup.json; exit"
```

</details>

<details open>
<summary><b>🔑 9. Liaison d'identifiants de clés physiques FIDO2 / Windows Hello (#64 - #70)</b></summary>
<br>

```bash
# 64. Inspecter les capacités matérielles de la plateforme hôte (Windows Hello, WebAuthn API)
svault fido2 status
svault fido2 status --json

# 65. Enregistrer une clé USB FIDO2 ou un identifiant Windows Hello
svault fido2 enroll yubikey-5c --type usb --user alice --output ./yubikey.json
svault fido2 enroll hello-tpm --type hello --pin 849201 --json

# 66. Tester l'assertion de l'authentificateur et vérifier l'empreinte de dérivation PRF
svault fido2 test ./yubikey.json
svault fido2 test ./yubikey.json --json

# 67. Chiffrer un conteneur en liant un identifiant FIDO2 et un mot de passe
svault encrypt -i secret.txt -o sealed.svault --fido2-cred ./yubikey.json -p "master-pass"

# 68. Déchiffrer un conteneur à l'aide de l'identifiant matériel enregistré
svault decrypt -i sealed.svault -o restored.txt --fido2-cred ./yubikey.json -p "master-pass"

# 69. Authentification multifacteur 2FA : Fichier clé + Jeton physique FIDO2 (sans mot de passe)
svault encrypt -i secret.txt -o mfa.svault -k usb_token.key --fido2-cred ./yubikey.json
svault decrypt -i mfa.svault -o restored.txt -k usb_token.key --fido2-cred ./yubikey.json

# 70. Renouveler un conteneur existant pour lier ou délier un identifiant matériel FIDO2
svault rotate -i sealed.svault --in-place -p "old-pass" -n "new-pass" --fido2 --fido2-cred ./yubikey.json
svault rotate -i sealed.svault --in-place -p "new-pass" -n "plain-pass" --no-fido2 --fido2-cred ./yubikey.json
```

</details>

<details open>
<summary><b>⚛️ 10. Encapsulation de clé hybride post-quantique (X25519 + ML-KEM-768) (#71 - #74)</b></summary>
<br>

```bash
# 71. Générer une paire de clés hybride post-quantique (X25519 + ML-KEM-768)
svault kem keygen -p recipient.pub -s recipient.key
svault kem keygen -p recipient.pub -s recipient.key --json

# 72. Sceller un fichier confidentiel pour la clé publique du destinataire (binaire ou ASCII)
svault kem seal -i classified.txt -o sealed.svault.pq -k recipient.pub
svault kem seal -i classified.txt -o sealed.asc -k recipient.pub --armor --json

# 73. Inspecter les métadonnées du conteneur post-quantique (clé éphémère, taille du texte chiffré, CRC-32)
svault kem inspect -i sealed.svault.pq
svault kem inspect -i sealed.asc --json

# 74. Ouvrir et déchiffrer le coffre post-quantique avec la clé privée du destinataire
svault kem open -i sealed.svault.pq -o restored.txt -k recipient.key
svault kem open -i sealed.asc -o restored.txt -k recipient.key --json
```

</details>

</details>

---

## 🔒 Sécurité mémoire et invariants de protection

<details open>
<summary><b>🔒 Sécurité mémoire et invariants de protection</b></summary>
<br>

- **100% Rust sûr et cryptographie en temps constant** : Aucun bloc `unsafe` dans les chemins de données sensibles ; calculs sans branchement dans les corps de Galois pour interdire toute attaque par canal auxiliaire liée au temps.
- **Effacement proactif et sécurisé de la mémoire** : Les calendriers de clés et mémoires tampons déclenchent une mise à zéro protégée contre les optimisations du compilateur à la destruction via `zeroize`.
- **Liaison au profil matériel** : L'encapsulation facultative par Windows DPAPI empêche toute lecture en dehors de la machine et de la session utilisateur d'origine.
- **Défense contre Zip Slip et les bombes de décompression** : Chemins relatifs stricts, contrôles drastiques et plafonds d'allocation mémoire pour prévenir tout déni de service.

</details>

---

## 📄 Licence et attribution

<details open>
<summary><b>📄 Licence et attribution</b></summary>
<br>

Copyright 2026 **GHSFS** ([https://github.com/GHSFS](https://github.com/GHSFS)).

Distribué sous la **Licence Apache, Version 2.0** ([`LICENSE`](../../LICENSE)).
Conformément à la section 4(d) de la licence Apache 2.0, toute redistribution ou travail dérivé doit conserver l'ensemble des mentions d'attribution contenues dans le fichier [`NOTICE`](../../NOTICE).

</details>
