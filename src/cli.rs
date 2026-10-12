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
        #[arg(short, long)]
        passphrase: String,

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

        /// Decoy passphrase (reveals only decoy file)
        #[arg(long = "decoy-passphrase")]
        decoy_passphrase: String,

        /// Explicit random padding bytes for size obfuscation
        #[arg(long, default_value_t = 0)]
        padding: usize,

        /// Bind container to the current Windows user/machine via DPAPI
        #[arg(long)]
        dpapi: bool,
    },

    /// Decrypt a .svault container back to its original file
    #[command(visible_alias = "dec")]
    Decrypt {
        /// Input .svault file path
        #[arg(short, long)]
        input: PathBuf,

        /// Output plaintext file path
        #[arg(short, long)]
        output: PathBuf,

        /// Decryption passphrase (unlocks either primary or decoy automatically)
        #[arg(short, long)]
        passphrase: Option<String>,

        /// Explicit decoy passphrase
        #[arg(long = "decoy-passphrase")]
        decoy_passphrase: Option<String>,
    },

    /// Decrypt a plausible deniability container (seamless or explicit decoy passphrase)
    #[command(name = "decrypt-decoy", visible_alias = "dec-decoy")]
    DecryptDecoy {
        /// Input .svault file path
        #[arg(short, long)]
        input: PathBuf,

        /// Output plaintext file path
        #[arg(short, long)]
        output: PathBuf,

        /// Decryption passphrase (unlocks either primary or decoy automatically)
        #[arg(short, long)]
        passphrase: Option<String>,

        /// Explicit decoy passphrase
        #[arg(long = "decoy-passphrase")]
        decoy_passphrase: Option<String>,
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
        #[arg(short, long)]
        passphrase: String,

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
    },

    /// Extract and decrypt a secret file from a stego PNG image
    #[command(visible_alias = "unhide")]
    Extract {
        /// Input stego PNG image path
        #[arg(short, long)]
        carrier: PathBuf,

        /// Output file path for extracted secret
        #[arg(short, long)]
        output: PathBuf,

        /// Decryption passphrase (unlocks either primary or decoy automatically)
        #[arg(short, long)]
        passphrase: Option<String>,

        /// Explicit decoy passphrase
        #[arg(long = "decoy-passphrase")]
        decoy_passphrase: Option<String>,
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
        #[arg(short, long)]
        passphrase: String,

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
    },

    /// Extract and decrypt a secret file from a stego WAV audio file
    #[command(name = "extract-wav", visible_alias = "unhide-wav")]
    ExtractWav {
        /// Input stego WAV audio path
        #[arg(short, long)]
        carrier: PathBuf,

        /// Output file path for extracted secret
        #[arg(short, long)]
        output: PathBuf,

        /// Decryption passphrase (unlocks either primary or decoy automatically)
        #[arg(short, long)]
        passphrase: Option<String>,

        /// Explicit decoy passphrase
        #[arg(long = "decoy-passphrase")]
        decoy_passphrase: Option<String>,

        /// Steganography mode (auto, chunk, or lsb)
        #[arg(short, long, value_enum, default_value_t = crate::wav::ExtractWavMode::Auto)]
        mode: crate::wav::ExtractWavMode,

        /// Use 16-bit PCM LSB mode (shorthand for --mode lsb)
        #[arg(long)]
        lsb: bool,
    },

    /// Inspect a .svault container or stego carrier header without decrypting
    Inspect {
        /// Target .svault, .png, or .wav file
        input: PathBuf,
    },

    /// Securely overwrite and destroy a sensitive file (3-pass shred)
    Shred {
        /// File to securely shred
        input: PathBuf,

        /// Number of overwrite passes (default: 3)
        #[arg(short, long, default_value_t = 3)]
        passes: u8,
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
}
