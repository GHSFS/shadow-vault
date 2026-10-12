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

        /// Decryption passphrase
        #[arg(short, long)]
        passphrase: String,
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

        /// Decryption passphrase
        #[arg(short, long)]
        passphrase: String,
    },

    /// Inspect a .svault container or stego PNG header without decrypting
    Inspect {
        /// Target .svault or .png file
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
}
