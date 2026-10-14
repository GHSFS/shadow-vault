// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "svault",
    version,
    about = "ShadowVault — steganography & dual-layer hardware-bound encrypted vault",
    long_about = None
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Encrypt a file into a .svault container (Argon2id + ChaCha20-Poly1305 + optional DPAPI)
    #[command(visible_alias = "enc")]
    Encrypt {
        /// Input file path
        #[arg(short, long)]
        input: PathBuf,

        /// Output .svault file path
        #[arg(short, long)]
        output: PathBuf,

        /// Encryption passphrase
        #[arg(short, long, required_unless_present = "keyfile")]
        passphrase: Option<String>,

        /// Optional external keyfile for 2FA or keyfile-only encryption
        #[arg(short = 'k', long = "keyfile")]
        keyfile: Option<PathBuf>,

        /// Optional decoy file to create a plausible deniability container
        #[arg(short = 'd', long = "decoy", requires = "decoy_passphrase")]
        decoy: Option<PathBuf>,

        /// Decoy passphrase when --decoy is specified
        #[arg(long = "decoy-passphrase", requires = "decoy")]
        decoy_passphrase: Option<String>,

        /// Explicit random padding bytes for size obfuscation
        #[arg(long, default_value_t = 0)]
        padding: usize,

        /// Bind container to the current Windows user/machine via DPAPI
        #[arg(long)]
        dpapi: bool,

        /// Time-lock activation timestamp or relative offset (e.g. "2026-10-15T00:00:00Z", "+1h")
        #[arg(long = "not-before")]
        not_before: Option<String>,

        /// Expiration timestamp after which decryption is refused (e.g. "2026-12-31T23:59:59Z")
        #[arg(long = "expires-at")]
        expires_at: Option<String>,

        /// Expiration duration from now (e.g. "24h", "7d", "30d", "3600s")
        #[arg(long = "expires-in")]
        expires_in: Option<String>,

        /// Optional descriptive label or policy comment
        #[arg(long = "policy-desc")]
        policy_desc: Option<String>,

        /// Use chunked streaming encryption mode (constant RAM for multi-GB files)
        #[arg(long = "stream")]
        stream: bool,

        /// Stream chunk size in bytes or with suffix (e.g. 4194304, 4m, 1m, 64k; default: 4 MiB)
        #[arg(long = "chunk-size")]
        chunk_size: Option<String>,

        /// Automatically arm vault with maximum attempt self-destruction guard
        #[arg(long = "max-attempts")]
        max_attempts: Option<u32>,

        /// Dead-man switch duration from now (e.g. "24h", "7d", "30d")
        #[arg(long = "dead-man")]
        dead_man: Option<String>,

        /// Store guard in companion file (<output>.guard) instead of stealth system ledger
        #[arg(long = "guard-companion")]
        guard_companion: bool,

        /// Output operation summary in structured JSON format
        #[arg(long)]
        json: bool,
    },

    /// Encrypt a dual-password container with primary hidden secret and plausible decoy
    #[command(name = "encrypt-decoy", visible_alias = "enc-decoy")]
    EncryptDecoy {
        /// Primary secret file to conceal
        #[arg(short = 'i', long = "primary", visible_alias = "input")]
        primary: PathBuf,

        /// Decoy file to show under coercion
        #[arg(short = 'd', long = "decoy")]
        decoy: PathBuf,

        /// Output .svault container file path
        #[arg(short = 'o', long = "output")]
        output: PathBuf,

        /// Primary secret passphrase
        #[arg(short = 'p', long = "passphrase")]
        passphrase: String,

        /// Optional external keyfile bound to primary secret
        #[arg(short = 'k', long = "keyfile")]
        keyfile: Option<PathBuf>,

        /// Decoy passphrase (reveals only decoy file)
        #[arg(long = "decoy-passphrase")]
        decoy_passphrase: String,

        /// Explicit random padding bytes for size obfuscation
        #[arg(long, default_value_t = 0)]
        padding: usize,

        /// Bind container to the current Windows user/machine via DPAPI
        #[arg(long)]
        dpapi: bool,

        /// Output operation summary in structured JSON format
        #[arg(long)]
        json: bool,
    },

    /// Decrypt a .svault container back to its original file
    #[command(visible_alias = "dec")]
    Decrypt {
        /// Input .svault file path
        #[arg(short, long)]
        input: PathBuf,

        /// Output plaintext file path (optional when --clip is provided)
        #[arg(short, long, required_unless_present = "clip")]
        output: Option<PathBuf>,

        /// Decryption passphrase (unlocks either primary or decoy automatically)
        #[arg(short, long)]
        passphrase: Option<String>,

        /// Optional external keyfile for 2FA or keyfile-only decryption
        #[arg(short = 'k', long = "keyfile")]
        keyfile: Option<PathBuf>,

        /// Explicit decoy passphrase
        #[arg(long = "decoy-passphrase")]
        decoy_passphrase: Option<String>,

        /// Copy decrypted plaintext to Windows clipboard with auto-expiring guard
        #[arg(long = "clip")]
        clip: bool,

        /// Auto-expiring clipboard time-to-live in seconds (default: 15)
        #[arg(long = "clip-ttl", default_value_t = 15)]
        clip_ttl: u64,

        /// Optional simulated reference UTC timestamp for policy validation
        #[arg(long = "at-time")]
        at_time: Option<String>,

        /// Explicit streaming container decryption mode
        #[arg(long = "stream")]
        stream: bool,

        /// Output operation summary in structured JSON format
        #[arg(long)]
        json: bool,
    },

    /// Decrypt a plausible deniability container (seamless or explicit decoy passphrase)
    #[command(name = "decrypt-decoy", visible_alias = "dec-decoy")]
    DecryptDecoy {
        /// Input .svault file path
        #[arg(short, long)]
        input: PathBuf,

        /// Output plaintext file path (optional when --clip is provided)
        #[arg(short, long, required_unless_present = "clip")]
        output: Option<PathBuf>,

        /// Decryption passphrase (unlocks either primary or decoy automatically)
        #[arg(short, long)]
        passphrase: Option<String>,

        /// Optional external keyfile bound to primary secret
        #[arg(short = 'k', long = "keyfile")]
        keyfile: Option<PathBuf>,

        /// Explicit decoy passphrase
        #[arg(long = "decoy-passphrase")]
        decoy_passphrase: Option<String>,

        /// Copy decrypted plaintext to Windows clipboard with auto-expiring guard
        #[arg(long = "clip")]
        clip: bool,

        /// Auto-expiring clipboard time-to-live in seconds (default: 15)
        #[arg(long = "clip-ttl", default_value_t = 15)]
        clip_ttl: u64,

        /// Optional simulated reference UTC timestamp for policy validation
        #[arg(long = "at-time")]
        at_time: Option<String>,

        /// Output operation summary in structured JSON format
        #[arg(long)]
        json: bool,
    },

    /// Encrypt and hide a secret file inside a PNG carrier image
    #[command(visible_alias = "hide")]
    Embed {
        /// Carrier PNG image path
        #[arg(short, long)]
        carrier: PathBuf,

        /// Secret file to encrypt and embed
        #[arg(short, long)]
        secret: PathBuf,

        /// Output stego PNG image path
        #[arg(short, long)]
        output: PathBuf,

        /// Encryption passphrase
        #[arg(short, long, required_unless_present = "keyfile")]
        passphrase: Option<String>,

        /// Optional external keyfile for 2FA or keyfile-only encryption
        #[arg(short = 'k', long = "keyfile")]
        keyfile: Option<PathBuf>,

        /// Optional decoy file to create a plausible deniability container
        #[arg(short = 'd', long = "decoy", requires = "decoy_passphrase")]
        decoy: Option<PathBuf>,

        /// Decoy passphrase when --decoy is specified
        #[arg(long = "decoy-passphrase", requires = "decoy")]
        decoy_passphrase: Option<String>,

        /// Explicit random padding bytes for size obfuscation
        #[arg(long, default_value_t = 0)]
        padding: usize,

        /// Bind hidden payload to the current Windows user/machine via DPAPI
        #[arg(long)]
        dpapi: bool,

        /// Time-lock activation timestamp or relative offset (e.g. "2026-10-15T00:00:00Z", "+1h")
        #[arg(long = "not-before")]
        not_before: Option<String>,

        /// Expiration timestamp after which decryption is refused (e.g. "2026-12-31T23:59:59Z")
        #[arg(long = "expires-at")]
        expires_at: Option<String>,

        /// Expiration duration from now (e.g. "24h", "7d", "30d", "3600s")
        #[arg(long = "expires-in")]
        expires_in: Option<String>,

        /// Optional descriptive label or policy comment
        #[arg(long = "policy-desc")]
        policy_desc: Option<String>,

        /// Output operation summary in structured JSON format
        #[arg(long)]
        json: bool,
    },

    /// Extract and decrypt a secret file from a stego PNG image
    #[command(visible_alias = "unhide")]
    Extract {
        /// Input stego PNG image path
        #[arg(short, long)]
        carrier: PathBuf,

        /// Output file path for extracted secret (optional when --clip is provided)
        #[arg(short, long, required_unless_present = "clip")]
        output: Option<PathBuf>,

        /// Decryption passphrase (unlocks either primary or decoy automatically)
        #[arg(short, long)]
        passphrase: Option<String>,

        /// Optional external keyfile for 2FA or keyfile-only extraction
        #[arg(short = 'k', long = "keyfile")]
        keyfile: Option<PathBuf>,

        /// Explicit decoy passphrase
        #[arg(long = "decoy-passphrase")]
        decoy_passphrase: Option<String>,

        /// Copy decrypted plaintext to Windows clipboard with auto-expiring guard
        #[arg(long = "clip")]
        clip: bool,

        /// Auto-expiring clipboard time-to-live in seconds (default: 15)
        #[arg(long = "clip-ttl", default_value_t = 15)]
        clip_ttl: u64,

        /// Optional simulated reference UTC timestamp for policy validation
        #[arg(long = "at-time")]
        at_time: Option<String>,

        /// Output operation summary in structured JSON format
        #[arg(long)]
        json: bool,
    },

    /// Encrypt and hide a secret file inside a WAV audio carrier
    #[command(name = "embed-wav", visible_alias = "hide-wav")]
    EmbedWav {
        /// Carrier WAV audio path
        #[arg(short, long)]
        carrier: PathBuf,

        /// Secret file to encrypt and embed
        #[arg(short, long)]
        secret: PathBuf,

        /// Output stego WAV audio path
        #[arg(short, long)]
        output: PathBuf,

        /// Encryption passphrase
        #[arg(short, long, required_unless_present = "keyfile")]
        passphrase: Option<String>,

        /// Optional external keyfile for 2FA or keyfile-only encryption
        #[arg(short = 'k', long = "keyfile")]
        keyfile: Option<PathBuf>,

        /// Steganography mode (chunk or lsb)
        #[arg(short, long, value_enum, default_value_t = crate::wav::WavMode::Chunk)]
        mode: crate::wav::WavMode,

        /// Use 16-bit PCM LSB mode (shorthand for --mode lsb)
        #[arg(long)]
        lsb: bool,

        /// Optional decoy file to create a plausible deniability container
        #[arg(short = 'd', long = "decoy", requires = "decoy_passphrase")]
        decoy: Option<PathBuf>,

        /// Decoy passphrase when --decoy is specified
        #[arg(long = "decoy-passphrase", requires = "decoy")]
        decoy_passphrase: Option<String>,

        /// Explicit random padding bytes for size obfuscation
        #[arg(long, default_value_t = 0)]
        padding: usize,

        /// Bind hidden payload to the current Windows user/machine via DPAPI
        #[arg(long)]
        dpapi: bool,

        /// Time-lock activation timestamp or relative offset (e.g. "2026-10-15T00:00:00Z", "+1h")
        #[arg(long = "not-before")]
        not_before: Option<String>,

        /// Expiration timestamp after which decryption is refused (e.g. "2026-12-31T23:59:59Z")
        #[arg(long = "expires-at")]
        expires_at: Option<String>,

        /// Expiration duration from now (e.g. "24h", "7d", "30d", "3600s")
        #[arg(long = "expires-in")]
        expires_in: Option<String>,

        /// Optional descriptive label or policy comment
        #[arg(long = "policy-desc")]
        policy_desc: Option<String>,

        /// Output operation summary in structured JSON format
        #[arg(long)]
        json: bool,
    },

    /// Extract and decrypt a secret file from a stego WAV audio file
    #[command(name = "extract-wav", visible_alias = "unhide-wav")]
    ExtractWav {
        /// Input stego WAV audio path
        #[arg(short, long)]
        carrier: PathBuf,

        /// Output file path for extracted secret (optional when --clip is provided)
        #[arg(short, long, required_unless_present = "clip")]
        output: Option<PathBuf>,

        /// Decryption passphrase (unlocks either primary or decoy automatically)
        #[arg(short, long)]
        passphrase: Option<String>,

        /// Optional external keyfile for 2FA or keyfile-only extraction
        #[arg(short = 'k', long = "keyfile")]
        keyfile: Option<PathBuf>,

        /// Explicit decoy passphrase
        #[arg(long = "decoy-passphrase")]
        decoy_passphrase: Option<String>,

        /// Steganography mode (auto, chunk, or lsb)
        #[arg(short, long, value_enum, default_value_t = crate::wav::ExtractWavMode::Auto)]
        mode: crate::wav::ExtractWavMode,

        /// Use 16-bit PCM LSB mode (shorthand for --mode lsb)
        #[arg(long)]
        lsb: bool,

        /// Copy decrypted plaintext to Windows clipboard with auto-expiring guard
        #[arg(long = "clip")]
        clip: bool,

        /// Auto-expiring clipboard time-to-live in seconds (default: 15)
        #[arg(long = "clip-ttl", default_value_t = 15)]
        clip_ttl: u64,

        /// Optional simulated reference UTC timestamp for policy validation
        #[arg(long = "at-time")]
        at_time: Option<String>,

        /// Output operation summary in structured JSON format
        #[arg(long)]
        json: bool,
    },

    /// Encrypt and hide a secret file inside a 24-bit uncompressed BMP carrier image
    #[command(name = "embed-bmp", visible_alias = "hide-bmp")]
    EmbedBmp {
        /// Carrier BMP image path
        #[arg(short, long)]
        carrier: PathBuf,

        /// Secret file to encrypt and embed
        #[arg(short, long)]
        secret: PathBuf,

        /// Output stego BMP image path
        #[arg(short, long)]
        output: PathBuf,

        /// Encryption passphrase
        #[arg(short, long, required_unless_present = "keyfile")]
        passphrase: Option<String>,

        /// Optional external keyfile for 2FA or keyfile-only encryption
        #[arg(short = 'k', long = "keyfile")]
        keyfile: Option<PathBuf>,

        /// Optional decoy file to create a plausible deniability container
        #[arg(short = 'd', long = "decoy", requires = "decoy_passphrase")]
        decoy: Option<PathBuf>,

        /// Decoy passphrase when --decoy is specified
        #[arg(long = "decoy-passphrase", requires = "decoy")]
        decoy_passphrase: Option<String>,

        /// Explicit random padding bytes for size obfuscation
        #[arg(long, default_value_t = 0)]
        padding: usize,

        /// Bind hidden payload to the current Windows user/machine via DPAPI
        #[arg(long)]
        dpapi: bool,

        /// Time-lock activation timestamp or relative offset (e.g. "2026-10-15T00:00:00Z", "+1h")
        #[arg(long = "not-before")]
        not_before: Option<String>,

        /// Expiration timestamp after which decryption is refused (e.g. "2026-12-31T23:59:59Z")
        #[arg(long = "expires-at")]
        expires_at: Option<String>,

        /// Expiration duration from now (e.g. "24h", "7d", "30d", "3600s")
        #[arg(long = "expires-in")]
        expires_in: Option<String>,

        /// Optional descriptive label or policy comment
        #[arg(long = "policy-desc")]
        policy_desc: Option<String>,

        /// Output operation summary in structured JSON format
        #[arg(long)]
        json: bool,
    },

    /// Extract and decrypt a secret file from a stego BMP image
    #[command(name = "extract-bmp", visible_alias = "unhide-bmp")]
    ExtractBmp {
        /// Input stego BMP image path
        #[arg(short, long)]
        carrier: PathBuf,

        /// Output file path for extracted secret (optional when --clip is provided)
        #[arg(short, long, required_unless_present = "clip")]
        output: Option<PathBuf>,

        /// Decryption passphrase (unlocks either primary or decoy automatically)
        #[arg(short, long)]
        passphrase: Option<String>,

        /// Optional external keyfile for 2FA or keyfile-only extraction
        #[arg(short = 'k', long = "keyfile")]
        keyfile: Option<PathBuf>,

        /// Explicit decoy passphrase
        #[arg(long = "decoy-passphrase")]
        decoy_passphrase: Option<String>,

        /// Copy decrypted plaintext to Windows clipboard with auto-expiring guard
        #[arg(long = "clip")]
        clip: bool,

        /// Auto-expiring clipboard time-to-live in seconds (default: 15)
        #[arg(long = "clip-ttl", default_value_t = 15)]
        clip_ttl: u64,

        /// Optional simulated reference UTC timestamp for policy validation
        #[arg(long = "at-time")]
        at_time: Option<String>,

        /// Output operation summary in structured JSON format
        #[arg(long)]
        json: bool,
    },

    /// Estimate and display steganographic data storage capacity for a carrier file
    #[command(name = "capacity", visible_alias = "cap")]
    Capacity {
        /// Carrier file path (.bmp, .wav, or .png)
        #[arg(value_name = "CARRIER")]
        carrier: PathBuf,

        /// Output carrier capacity report in structured JSON format
        #[arg(long)]
        json: bool,
    },

    /// Inspect a .svault container or stego carrier header without decrypting
    Inspect {
        /// Target .svault, .png, .wav, or .bmp file
        input: PathBuf,

        /// Output inspection report in structured JSON format
        #[arg(long)]
        json: bool,
    },

    /// Securely overwrite and destroy a sensitive file (3-pass shred)
    Shred {
        /// File to securely shred
        input: PathBuf,

        /// Number of overwrite passes (default: 3)
        #[arg(short, long, default_value_t = 3)]
        passes: u8,

        /// Output operation summary in structured JSON format
        #[arg(long)]
        json: bool,
    },

    /// Split a secret or master recovery key into M-of-N Shamir shares (GF(256))
    #[command(name = "split", visible_alias = "share")]
    Split {
        /// Input file containing secret or master key (use '-' for stdin)
        #[arg(short, long, conflicts_with = "secret")]
        input: Option<PathBuf>,

        /// Direct text secret or passphrase to split
        #[arg(short, long, conflicts_with = "input")]
        secret: Option<String>,

        /// Threshold of shares required to reconstruct the secret (2..=255)
        #[arg(short = 'm', long = "threshold", default_value_t = 3)]
        threshold: u8,

        /// Total number of shares to generate (threshold..=255)
        #[arg(short = 'n', long = "shares", default_value_t = 5)]
        shares: u8,

        /// Output path prefix to save shares as files (e.g. 'share' writes 'share_1.share')
        #[arg(short, long)]
        output_prefix: Option<PathBuf>,

        /// Output shares in JSON array format
        #[arg(long)]
        json: bool,

        /// Output shares in compact single-line format
        #[arg(long)]
        compact: bool,
    },

    /// Combine M-of-N Shamir shares to reconstruct the original secret
    #[command(
        name = "combine",
        visible_alias = "recover",
        visible_alias = "reconstruct"
    )]
    Combine {
        /// Share files or armored share strings to combine
        #[arg(value_name = "SHARES")]
        shares: Vec<String>,

        /// Output file path for reconstructed secret (if omitted, writes to stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Force raw binary output when writing to stdout
        #[arg(long)]
        raw: bool,

        /// Output recovery result in structured JSON format
        #[arg(long)]
        json: bool,
    },

    /// Armor a .svault container or secret file with Cauchy MDS Reed-Solomon parity stripes (.svault.asc)
    #[command(name = "armor", visible_alias = "asc")]
    Armor {
        /// Input file to armor (.svault container or binary file)
        #[arg(short, long)]
        input: PathBuf,

        /// Output armored file path (.svault.asc, defaults to stdout if omitted)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Number of data stripes K (default: 4, 1..=128)
        #[arg(short = 'k', long = "data-stripes", default_value_t = 4)]
        data_stripes: u8,

        /// Number of Cauchy MDS parity stripes M (default: 2, 1..=128)
        #[arg(short = 'm', long = "parity-stripes", default_value_t = 2)]
        parity_stripes: u8,

        /// Copy armored text to Windows clipboard with auto-expiring guard
        #[arg(long = "clip")]
        clip: bool,

        /// Auto-expiring clipboard time-to-live in seconds (default: 15)
        #[arg(long = "clip-ttl", default_value_t = 15)]
        clip_ttl: u64,

        /// Output operation summary in structured JSON format
        #[arg(long)]
        json: bool,
    },

    /// Decode an ASCII armored file (.svault.asc) back to the original container or secret file
    #[command(
        name = "dearmor",
        visible_alias = "de-armor",
        visible_alias = "unarmor"
    )]
    Dearmor {
        /// Input armored file (.svault.asc)
        #[arg(short, long)]
        input: PathBuf,

        /// Output binary file path (required unless --clip is specified)
        #[arg(short, long, required_unless_present = "clip")]
        output: Option<PathBuf>,

        /// Copy dearmored data to Windows clipboard with auto-expiring guard
        #[arg(long = "clip")]
        clip: bool,

        /// Auto-expiring clipboard time-to-live in seconds (default: 15)
        #[arg(long = "clip-ttl", default_value_t = 15)]
        clip_ttl: u64,

        /// Output operation summary in structured JSON format
        #[arg(long)]
        json: bool,
    },

    /// Inspect and repair a corrupted .svault.asc armored file using Cauchy Reed-Solomon parity
    #[command(name = "repair", visible_alias = "fix")]
    Repair {
        /// Corrupted armored file path (.svault.asc)
        #[arg(short, long)]
        input: PathBuf,

        /// Output repaired file path (.svault.asc or binary if --binary is set)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Output repaired container directly as binary instead of re-armoring
        #[arg(long = "binary", visible_alias = "raw")]
        binary: bool,

        /// Output repair diagnostic report in structured JSON format
        #[arg(long)]
        json: bool,

        /// Copy repaired content to Windows clipboard with auto-expiring guard
        #[arg(long = "clip")]
        clip: bool,

        /// Auto-expiring clipboard time-to-live in seconds (default: 15)
        #[arg(long = "clip-ttl", default_value_t = 15)]
        clip_ttl: u64,
    },

    /// Audit passphrase strength, Shannon entropy, and steganography carrier anomalies
    #[command(name = "audit")]
    Audit {
        /// Target file to audit (.svault container, stego carrier, or secret key file)
        #[arg(value_name = "TARGET")]
        target: Option<PathBuf>,

        /// Direct passphrase to audit for strength, entropy, and vulnerability patterns
        #[arg(short, long)]
        passphrase: Option<String>,

        /// Output audit report in structured JSON format
        #[arg(long)]
        json: bool,
    },

    /// Manage encrypted RFC 6238 TOTP 2FA vault (.svault)
    #[command(name = "totp", visible_alias = "2fa")]
    Totp {
        #[command(subcommand)]
        action: TotpAction,
    },

    /// Securely manage and guard clipboard with auto-expiring TTL and history suppression
    #[command(name = "clip", visible_alias = "clipboard")]
    Clip {
        #[command(subcommand)]
        action: ClipAction,
    },

    /// Pack an entire directory tree into an encrypted .svault container or carrier
    #[command(name = "pack-dir", visible_alias = "pack")]
    PackDir {
        /// Input directory to pack
        #[arg(short, long)]
        input: PathBuf,

        /// Output .svault container or carrier file path
        #[arg(short, long)]
        output: PathBuf,

        /// Encryption passphrase
        #[arg(short, long, required_unless_present = "keyfile")]
        passphrase: Option<String>,

        /// Optional external keyfile for 2FA or keyfile-only encryption
        #[arg(short = 'k', long = "keyfile")]
        keyfile: Option<PathBuf>,

        /// Bind container to current Windows user/machine via DPAPI
        #[arg(long)]
        dpapi: bool,

        /// Export as ASCII-armored document (.svault.asc)
        #[arg(long)]
        armor: bool,

        /// Optional carrier file (.png, .wav, .bmp) to embed archive into
        #[arg(long)]
        carrier: Option<PathBuf>,

        /// List files being packed
        #[arg(short, long)]
        list: bool,

        /// Time-lock activation timestamp or relative offset (e.g. "2026-10-15T00:00:00Z", "+1h")
        #[arg(long = "not-before")]
        not_before: Option<String>,

        /// Expiration timestamp after which decryption is refused (e.g. "2026-12-31T23:59:59Z")
        #[arg(long = "expires-at")]
        expires_at: Option<String>,

        /// Expiration duration from now (e.g. "24h", "7d", "30d", "3600s")
        #[arg(long = "expires-in")]
        expires_in: Option<String>,

        /// Optional descriptive label or policy comment
        #[arg(long = "policy-desc")]
        policy_desc: Option<String>,

        /// Output summary report in structured JSON format
        #[arg(long)]
        json: bool,
    },

    /// Unpack an encrypted .svault container or carrier back into directory
    #[command(name = "unpack-dir", visible_alias = "unpack")]
    UnpackDir {
        /// Input .svault container or stego/armor carrier file path
        #[arg(short, long)]
        input: PathBuf,

        /// Destination directory to extract files into (optional when --list or --verify-only is used)
        #[arg(short, long, required_unless_present_any = ["list", "verify_only"])]
        output: Option<PathBuf>,

        /// Decryption passphrase
        #[arg(short, long)]
        passphrase: Option<String>,

        /// Optional external keyfile for 2FA or keyfile-only decryption
        #[arg(short = 'k', long = "keyfile")]
        keyfile: Option<PathBuf>,

        /// List archive contents without extracting
        #[arg(short, long)]
        list: bool,

        /// Verify per-file SHA-256 digests and integrity without writing to disk
        #[arg(long)]
        verify_only: bool,

        /// Overwrite existing destination files
        #[arg(long)]
        overwrite: bool,

        /// Optional simulated reference UTC timestamp for policy validation
        #[arg(long = "at-time")]
        at_time: Option<String>,

        /// Output archive listing or verification report in structured JSON format
        #[arg(long)]
        json: bool,
    },

    /// Manage cryptographic keyfiles for two-factor (2FA) container sealing
    #[command(name = "keyfile")]
    Keyfile {
        #[command(subcommand)]
        action: KeyfileAction,
    },

    /// Chunked streaming encryption and decryption for multi-GB files (constant RAM)
    #[command(name = "stream")]
    Stream {
        #[command(subcommand)]
        action: StreamAction,
    },

    /// Compare original carrier vs. stego carrier and generate visual/statistical diff report
    #[command(name = "compare", visible_alias = "diff")]
    Compare {
        /// Original reference carrier or file path
        #[arg(value_name = "ORIGINAL")]
        original: PathBuf,

        /// Stego or modified carrier or file path
        #[arg(value_name = "STEGO")]
        stego: PathBuf,

        /// Output comparison report in structured JSON format
        #[arg(long)]
        json: bool,

        /// Display extended per-channel histogram and modified byte spans
        #[arg(long)]
        detailed: bool,
    },

    /// Dead-Man's switch and maximum attempt self-destruction guard management
    #[command(name = "guard")]
    Guard {
        #[command(subcommand)]
        action: GuardAction,
    },

    /// Generate cryptographically secure passphrases, recovery words, or random keys
    #[command(name = "keygen", visible_alias = "passgen", visible_alias = "gen-key")]
    Keygen {
        /// Number of Diceware recovery words to generate (BIP-39 dictionary, e.g. 6)
        #[arg(short = 'w', long = "words")]
        words: Option<usize>,

        /// Word separator character or string for Diceware mode (default: "-")
        #[arg(long = "separator", default_value = "-")]
        separator: String,

        /// Capitalize each Diceware word (TitleCase)
        #[arg(long = "capitalize")]
        capitalize: bool,

        /// Append a random numeric digit (0-9) to each Diceware word
        #[arg(long = "number")]
        number: bool,

        /// Generate random character passphrase of specified length (default: 20 if no words/bytes specified)
        #[arg(short = 'l', long = "length", visible_alias = "chars")]
        length: Option<usize>,

        /// Exclude punctuation symbols from generated passphrase
        #[arg(long = "no-symbols")]
        no_symbols: bool,

        /// Exclude numeric digits (0-9) from generated passphrase
        #[arg(long = "no-numbers")]
        no_numbers: bool,

        /// Exclude uppercase letters (A-Z) from generated passphrase
        #[arg(long = "no-upper")]
        no_upper: bool,

        /// Exclude visually ambiguous characters (0, O, o, 1, l, I, 8, B, |)
        #[arg(long = "exclude-ambiguous")]
        exclude_ambiguous: bool,

        /// Generate raw CSPRNG random bytes (hex-encoded by default)
        #[arg(short = 'b', long = "bytes")]
        bytes: Option<usize>,

        /// Output raw bytes in Base64 format instead of hexadecimal
        #[arg(long = "base64")]
        base64: bool,

        /// Output raw bytes in Base32 format (compatible with RFC 6238 TOTP secrets)
        #[arg(long = "base32")]
        base32: bool,

        /// Generate numeric PIN of specified length
        #[arg(long = "pin")]
        pin: Option<usize>,

        /// Optional master seed string for deterministic reproducible generation
        #[arg(short = 's', long = "seed")]
        seed: Option<String>,

        /// Optional salt or context string when using deterministic --seed
        #[arg(long = "context")]
        context: Option<String>,

        /// Number of candidate passphrases to generate (default: 1)
        #[arg(short = 'n', long = "count", default_value_t = 1)]
        count: usize,

        /// Output generated passphrase in structured JSON format
        #[arg(long)]
        json: bool,

        /// Display detailed keyspace and Shannon entropy analysis table
        #[arg(long)]
        entropy: bool,

        /// Securely copy generated passphrase to clipboard with auto-expiring guard
        #[arg(long)]
        clip: bool,

        /// Auto-expiring clipboard guard time-to-live in seconds (default: 15)
        #[arg(long = "clip-ttl", default_value_t = 15)]
        clip_ttl: u64,
    },

    /// Re-key an existing vault container or stego carrier with a new passphrase or keyfile
    #[command(name = "rotate", visible_alias = "rekey")]
    Rotate {
        /// Input .svault container or carrier file path
        #[arg(short = 'i', long = "input")]
        input: PathBuf,

        /// Output .svault container or carrier file path (optional when --in-place is specified)
        #[arg(
            short = 'o',
            long = "output",
            required_unless_present = "in_place",
            conflicts_with = "in_place"
        )]
        output: Option<PathBuf>,

        /// Overwrite input container or carrier in-place atomically
        #[arg(long = "in-place", conflicts_with = "output")]
        in_place: bool,

        /// Current (old) decryption passphrase
        #[arg(short = 'p', long = "old-passphrase")]
        old_passphrase: Option<String>,

        /// New encryption passphrase
        #[arg(short = 'n', long = "new-passphrase")]
        new_passphrase: Option<String>,

        /// Optional current (old) keyfile path
        #[arg(long = "old-keyfile")]
        old_keyfile: Option<PathBuf>,

        /// Optional new keyfile path
        #[arg(long = "new-keyfile")]
        new_keyfile: Option<PathBuf>,

        /// Explicitly bind rotated container with Windows DPAPI hardware protection
        #[arg(long = "dpapi", conflicts_with = "no_dpapi")]
        dpapi: bool,

        /// Explicitly remove Windows DPAPI hardware binding
        #[arg(long = "no-dpapi", conflicts_with = "dpapi")]
        no_dpapi: bool,

        /// Strip and clear existing time-lock / expiration policy header
        #[arg(long = "clear-policy")]
        clear_policy: bool,

        /// Output rotation summary in structured JSON format
        #[arg(long)]
        json: bool,
    },

    /// Detached integrity manifest and tamper canary verification
    #[command(name = "canary", visible_alias = "manifest")]
    Canary {
        #[command(subcommand)]
        action: CanaryAction,
    },

    /// Interactive in-memory terminal vault shell for key-value secrets
    #[command(name = "repl", visible_alias = "shell")]
    Repl {
        /// Path to encrypted .svault key-value container (opens existing or creates new)
        #[arg(short = 'v', long = "vault", default_value = "vault.svault")]
        vault: PathBuf,

        /// Decryption/encryption passphrase
        #[arg(short, long)]
        passphrase: Option<String>,

        /// Optional external keyfile for 2FA or keyfile-only authentication
        #[arg(short = 'k', long = "keyfile")]
        keyfile: Option<PathBuf>,

        /// Bind container to current Windows user/machine via DPAPI
        #[arg(long)]
        dpapi: bool,

        /// Open session in read-only mode (prohibits set, del, save)
        #[arg(long)]
        readonly: bool,

        /// Execute command string (single or semicolon-separated) and exit immediately
        #[arg(short = 'e', long = "exec")]
        exec: Option<String>,

        /// Automatically save modifications back to encrypted vault upon exit
        #[arg(long = "auto-save")]
        auto_save: bool,

        /// Output operation results in structured JSON format
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum StreamAction {
    /// Encrypt a large file or stream into a .svault streaming container
    #[command(visible_alias = "enc")]
    Encrypt {
        /// Input file path
        #[arg(short, long)]
        input: PathBuf,

        /// Output .svault streaming container file path
        #[arg(short, long)]
        output: PathBuf,

        /// Encryption passphrase
        #[arg(short, long, required_unless_present = "keyfile")]
        passphrase: Option<String>,

        /// Optional external keyfile for 2FA or keyfile-only encryption
        #[arg(short = 'k', long = "keyfile")]
        keyfile: Option<PathBuf>,

        /// Bind container to the current Windows user/machine via DPAPI
        #[arg(long)]
        dpapi: bool,

        /// Stream chunk size in bytes or with suffix (e.g. 4194304, 4m, 1m, 64k; default: 4 MiB)
        #[arg(long = "chunk-size")]
        chunk_size: Option<String>,

        /// Time-lock activation timestamp or relative offset (e.g. "2026-10-15T00:00:00Z", "+1h")
        #[arg(long = "not-before")]
        not_before: Option<String>,

        /// Expiration timestamp after which decryption is refused (e.g. "2026-12-31T23:59:59Z")
        #[arg(long = "expires-at")]
        expires_at: Option<String>,

        /// Expiration duration from now (e.g. "24h", "7d", "30d", "3600s")
        #[arg(long = "expires-in")]
        expires_in: Option<String>,

        /// Optional descriptive label or policy comment
        #[arg(long = "policy-desc")]
        policy_desc: Option<String>,

        /// Output operation summary in structured JSON format
        #[arg(long)]
        json: bool,
    },

    /// Decrypt a .svault streaming container back to original file
    #[command(visible_alias = "dec")]
    Decrypt {
        /// Input .svault streaming container file path
        #[arg(short, long)]
        input: PathBuf,

        /// Output plaintext file path
        #[arg(short, long)]
        output: PathBuf,

        /// Decryption passphrase
        #[arg(short, long)]
        passphrase: Option<String>,

        /// Optional external keyfile for 2FA or keyfile-only decryption
        #[arg(short = 'k', long = "keyfile")]
        keyfile: Option<PathBuf>,

        /// Optional simulated reference UTC timestamp for policy validation
        #[arg(long = "at-time")]
        at_time: Option<String>,

        /// Output operation summary in structured JSON format
        #[arg(long)]
        json: bool,
    },

    /// Inspect a .svault streaming container header without decrypting
    Inspect {
        /// Target .svault streaming container file path
        #[arg(value_name = "TARGET")]
        input: PathBuf,

        /// Output inspection report in structured JSON format
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum KeyfileAction {
    /// Generate a cryptographically secure random keyfile
    #[command(visible_alias = "gen")]
    Generate {
        /// Output path for the generated keyfile
        #[arg(short, long)]
        output: PathBuf,

        /// Keyfile size in bytes (min: 16, max: 1048576, default: 64)
        #[arg(short, long, default_value_t = 64)]
        bytes: usize,

        /// Output operation summary in structured JSON format
        #[arg(long)]
        json: bool,
    },

    /// Inspect a keyfile's size, SHA-256 fingerprint, and Shannon entropy
    Inspect {
        /// Path to the keyfile to inspect
        #[arg(value_name = "KEYFILE")]
        path: PathBuf,

        /// Output inspection report in structured JSON format
        #[arg(long)]
        json: bool,
    },

    /// Calculate and display SHA-256 fingerprint of a keyfile
    Fingerprint {
        /// Path to the keyfile
        #[arg(value_name = "KEYFILE")]
        path: PathBuf,

        /// Output fingerprint in structured JSON format
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum TotpAction {
    /// Add a new TOTP 2FA secret or URI to the encrypted vault
    #[command(visible_alias = "new")]
    Add {
        /// Account name or identifier (e.g. 'GitHub:alice' or 'alice@example.com')
        #[arg(value_name = "NAME")]
        name: Option<String>,

        /// Base32 secret key (e.g. 'JBSWY3DPEHPK3PXP')
        #[arg(short, long)]
        secret: Option<String>,

        /// Key URI in 'otpauth://totp/...' format
        #[arg(short, long)]
        uri: Option<String>,

        /// Optional issuer name (e.g. 'GitHub', 'Google')
        #[arg(short, long)]
        issuer: Option<String>,

        /// Hash algorithm (SHA1, SHA256, SHA512; default: SHA1)
        #[arg(long, default_value = "SHA1")]
        algorithm: String,

        /// Number of OTP digits (6..=8; default: 6)
        #[arg(short, long, default_value_t = 6)]
        digits: u32,

        /// Time step period in seconds (default: 30)
        #[arg(long, default_value_t = 30)]
        period: u64,

        /// Path to the encrypted .svault container
        #[arg(short, long, default_value = "totp.svault")]
        vault: PathBuf,

        /// Encryption passphrase for the vault
        #[arg(short, long)]
        passphrase: String,

        /// Bind container to current Windows user/machine via DPAPI
        #[arg(long)]
        dpapi: bool,

        /// Output operation summary in structured JSON format
        #[arg(long)]
        json: bool,
    },

    /// Generate the current live 2FA code for an account
    #[command(visible_alias = "get", visible_alias = "gen")]
    Code {
        /// Account name or identifier
        #[arg(value_name = "NAME")]
        name: String,

        /// Explicit timestamp in seconds since Unix epoch (for testing/reproducibility)
        #[arg(short, long)]
        time: Option<u64>,

        /// Path to the encrypted .svault container
        #[arg(short, long, default_value = "totp.svault")]
        vault: PathBuf,

        /// Decryption passphrase for the vault
        #[arg(short, long)]
        passphrase: String,

        /// Output generated code in structured JSON format
        #[arg(long)]
        json: bool,

        /// Copy generated 2FA code to Windows clipboard with auto-expiring guard
        #[arg(long = "clip")]
        clip: bool,

        /// Auto-expiring clipboard time-to-live in seconds (default: 15)
        #[arg(long = "clip-ttl", default_value_t = 15)]
        clip_ttl: u64,
    },

    /// List all 2FA accounts stored in the encrypted vault
    #[command(visible_alias = "ls")]
    List {
        /// Path to the encrypted .svault container
        #[arg(short, long, default_value = "totp.svault")]
        vault: PathBuf,

        /// Decryption passphrase for the vault
        #[arg(short, long)]
        passphrase: String,

        /// Output account list in structured JSON format
        #[arg(long)]
        json: bool,
    },

    /// Remove an account from the encrypted vault
    #[command(visible_alias = "rm", visible_alias = "delete")]
    Remove {
        /// Account name or identifier to remove
        #[arg(value_name = "NAME")]
        name: String,

        /// Path to the encrypted .svault container
        #[arg(short, long, default_value = "totp.svault")]
        vault: PathBuf,

        /// Vault passphrase
        #[arg(short, long)]
        passphrase: String,

        /// Re-bind container with DPAPI upon saving
        #[arg(long)]
        dpapi: bool,

        /// Output operation summary in structured JSON format
        #[arg(long)]
        json: bool,
    },

    /// Verify a TOTP code against an account with time skew tolerance
    #[command(visible_alias = "check")]
    Verify {
        /// Account name or identifier
        #[arg(value_name = "NAME")]
        name: String,

        /// 6-to-8 digit OTP code to verify
        #[arg(value_name = "CODE")]
        code: String,

        /// Time skew tolerance in periods (default: 1, checks t-1, t, t+1)
        #[arg(short, long, default_value_t = 1)]
        skew: u32,

        /// Explicit timestamp in seconds since Unix epoch (for testing)
        #[arg(short, long)]
        time: Option<u64>,

        /// Path to the encrypted .svault container
        #[arg(short, long, default_value = "totp.svault")]
        vault: PathBuf,

        /// Decryption passphrase for the vault
        #[arg(short, long)]
        passphrase: String,

        /// Output verification result in structured JSON format
        #[arg(long)]
        json: bool,
    },

    /// Import TOTP secret or key URI into the vault
    Import {
        /// Key URI in 'otpauth://totp/...' format
        #[arg(short, long)]
        uri: Option<String>,

        /// File containing one or more otpauth URIs or JSON records
        #[arg(short, long)]
        file: Option<PathBuf>,

        /// Path to the encrypted .svault container
        #[arg(short, long, default_value = "totp.svault")]
        vault: PathBuf,

        /// Vault passphrase
        #[arg(short, long)]
        passphrase: String,

        /// Bind container with DPAPI
        #[arg(long)]
        dpapi: bool,

        /// Output operation summary in structured JSON format
        #[arg(long)]
        json: bool,
    },

    /// Export account record as standard 'otpauth://totp/...' URI
    Export {
        /// Account name or identifier to export (if omitted, exports all)
        #[arg(value_name = "NAME")]
        name: Option<String>,

        /// Path to the encrypted .svault container
        #[arg(short, long, default_value = "totp.svault")]
        vault: PathBuf,

        /// Vault passphrase
        #[arg(short, long)]
        passphrase: String,

        /// Output export records in structured JSON format
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum ClipAction {
    /// Copy text or secret to Windows clipboard and guard with auto-expiring TTL
    #[command(visible_alias = "set")]
    Copy {
        /// Text or secret to copy to clipboard
        #[arg(value_name = "TEXT")]
        text: String,

        /// Auto-expiring clipboard time-to-live in seconds (default: 15, 0 = copy without countdown)
        #[arg(short, long, default_value_t = 15)]
        ttl: u64,

        /// Suppress terminal countdown progress bar
        #[arg(short, long)]
        quiet: bool,

        /// Output operation summary in structured JSON format
        #[arg(long)]
        json: bool,
    },

    /// Read and output current Unicode text from clipboard
    #[command(visible_alias = "get", visible_alias = "read")]
    Paste {
        /// Output in structured JSON format
        #[arg(long)]
        json: bool,
    },

    /// Unconditionally wipe the system clipboard
    #[command(visible_alias = "wipe", visible_alias = "empty")]
    Clear {
        /// Output operation summary in structured JSON format
        #[arg(long)]
        json: bool,
    },

    /// Inspect current clipboard status (format, history suppression, length)
    #[command(visible_alias = "info")]
    Status {
        /// Output in structured JSON format
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum GuardAction {
    /// Arm a target container or carrier with max-attempt and/or dead-man switch guard
    #[command(visible_alias = "enable")]
    Arm {
        /// Target file to protect
        #[arg(short, long)]
        target: PathBuf,

        /// Maximum consecutive failed passphrase attempts before self-shred (default: 3)
        #[arg(short, long, default_value_t = 3)]
        max_attempts: u32,

        /// Dead-man switch duration from now (e.g. "24h", "7d", "30d")
        #[arg(long = "dead-man")]
        dead_man: Option<String>,

        /// Explicit dead-man deadline timestamp (ISO-8601 UTC)
        #[arg(long = "deadline")]
        deadline: Option<String>,

        /// Overwrite passes on self-destruction (default: 3)
        #[arg(long = "passes", default_value_t = 3)]
        passes: u8,

        /// Store guard in companion file (<target>.guard) instead of stealth system ledger
        #[arg(long = "companion")]
        companion: bool,

        /// Output in JSON format
        #[arg(long)]
        json: bool,
    },

    /// Inspect current guard status and attempt metrics
    #[command(visible_alias = "inspect")]
    Status {
        /// Target file
        #[arg(short, long)]
        target: PathBuf,

        /// Output in JSON format
        #[arg(long)]
        json: bool,

        /// Simulated reference timestamp (ISO-8601 UTC or relative duration)
        #[arg(long = "at-time")]
        at_time: Option<String>,
    },

    /// Reset failed attempts counter back to zero
    Reset {
        /// Target file
        #[arg(short, long)]
        target: PathBuf,

        /// Output in JSON format
        #[arg(long)]
        json: bool,
    },

    /// Check-in to refresh dead-man switch deadline
    Checkin {
        /// Target file
        #[arg(short, long)]
        target: PathBuf,

        /// Optional new duration interval (e.g. "24h", "7d")
        #[arg(long = "interval")]
        interval: Option<String>,

        /// Output in JSON format
        #[arg(long)]
        json: bool,
    },

    /// Disarm and remove guard protection from target
    #[command(visible_alias = "disable")]
    Disarm {
        /// Target file
        #[arg(short, long)]
        target: PathBuf,

        /// Output in JSON format
        #[arg(long)]
        json: bool,
    },

    /// Manually trigger immediate emergency multi-pass self-shred
    Trigger {
        /// Target file to permanently shred
        #[arg(short, long)]
        target: PathBuf,

        /// Number of overwrite passes (default: 3)
        #[arg(long = "passes", default_value_t = 3)]
        passes: u8,

        /// Confirm destructive emergency self-shred without prompting
        #[arg(long = "force")]
        force: bool,

        /// Output in JSON format
        #[arg(long)]
        json: bool,
    },

    /// List all actively guarded targets in the stealth ledger
    List {
        /// Output in JSON format
        #[arg(long)]
        json: bool,

        /// Simulated reference timestamp
        #[arg(long = "at-time")]
        at_time: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
pub enum CanaryAction {
    /// Initialize a signed tamper canary manifest for a directory of containers/carriers
    #[command(name = "init", visible_alias = "create", visible_alias = "generate")]
    Init {
        /// Target directory or file to track (defaults to '.')
        #[arg(short = 'd', long = "dir", default_value = ".")]
        dir: PathBuf,

        /// Output manifest file path (defaults to '<dir>/.svault-canary.json')
        #[arg(short = 'o', long = "output")]
        output: Option<PathBuf>,

        /// Optional passphrase to HMAC-sign the canary manifest
        #[arg(short = 'p', long = "passphrase")]
        passphrase: Option<String>,

        /// Optional keyfile to bind to the canary signature
        #[arg(short = 'k', long = "keyfile")]
        keyfile: Option<PathBuf>,

        /// Track all regular files, not just recognized vault/stego carriers
        #[arg(short = 'a', long = "all")]
        all: bool,

        /// Output operation summary in structured JSON format
        #[arg(long)]
        json: bool,
    },

    /// Verify an integrity manifest against on-disk files and detect tampering or missing files
    #[command(name = "verify", visible_alias = "check", visible_alias = "audit")]
    Verify {
        /// Target directory or file to verify against (defaults to '.')
        #[arg(short = 'd', long = "dir", default_value = ".")]
        dir: PathBuf,

        /// Path to the canary manifest file (defaults to '<dir>/.svault-canary.json')
        #[arg(short = 'm', long = "manifest")]
        manifest: Option<PathBuf>,

        /// Passphrase used when signing the canary manifest
        #[arg(short = 'p', long = "passphrase")]
        passphrase: Option<String>,

        /// Keyfile used when signing the canary manifest
        #[arg(short = 'k', long = "keyfile")]
        keyfile: Option<PathBuf>,

        /// Fail verification if untracked files are found in target directory
        #[arg(long = "strict")]
        strict: bool,

        /// Output verification report in structured JSON format
        #[arg(long)]
        json: bool,
    },
}
