// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use crate::error::Result;
use crate::pq_kem::keys::{HybridKeyPair, HybridPrivateKey, HybridPublicKey};
use crate::pq_kem::{inspect_pq_vault, open_pq_vault, seal_pq_vault};
use clap::{Args, Subcommand};
use colored::Colorize;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Subcommand)]
pub enum KemSubcommands {
    /// Generate a new post-quantum hybrid keypair (X25519 + ML-KEM-768)
    #[command(name = "keygen", visible_alias = "gen")]
    Keygen(KemKeygenArgs),

    /// Seal a file using post-quantum hybrid key encapsulation
    #[command(name = "seal", visible_alias = "enc")]
    Seal(KemSealArgs),

    /// Open a file sealed with post-quantum hybrid key encapsulation
    #[command(name = "open", visible_alias = "dec")]
    Open(KemOpenArgs),

    /// Inspect a post-quantum sealed container or key file
    #[command(name = "inspect", visible_alias = "info")]
    Inspect(KemInspectArgs),
}

#[derive(Debug, Args)]
pub struct KemKeygenArgs {
    /// Optional path to write recipient public key file
    #[arg(short = 'p', long = "pubkey")]
    pub pubkey: Option<PathBuf>,

    /// Optional path to write private key file
    #[arg(short = 's', long = "privkey", visible_alias = "seckey")]
    pub privkey: Option<PathBuf>,

    /// Write keys in ASCII armored format (default: true)
    #[arg(long, default_value_t = true)]
    pub armor: bool,

    /// Output report in structured JSON format
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct KemSealArgs {
    /// Input plaintext file path
    #[arg(short, long)]
    pub input: PathBuf,

    /// Output encrypted container file path (.svault.pq or .asc)
    #[arg(short, long)]
    pub output: PathBuf,

    /// Recipient public key (file path or armored string)
    #[arg(short = 'k', long = "pubkey", visible_alias = "recipient")]
    pub pubkey: String,

    /// Output container in ASCII armored format
    #[arg(long)]
    pub armor: bool,

    /// Output report in structured JSON format
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct KemOpenArgs {
    /// Input encrypted container file path (.svault.pq or .asc)
    #[arg(short, long)]
    pub input: PathBuf,

    /// Output decrypted plaintext file path
    #[arg(short, long)]
    pub output: PathBuf,

    /// Recipient private key (file path or armored string)
    #[arg(short = 'k', long = "privkey", visible_alias = "seckey")]
    pub privkey: String,

    /// Output report in structured JSON format
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct KemInspectArgs {
    /// Input container file path
    #[arg(short, long)]
    pub input: PathBuf,

    /// Output report in structured JSON format
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KemKeygenReport {
    pub algorithm: String,
    pub fingerprint: String,
    pub pubkey_file: Option<String>,
    pub privkey_file: Option<String>,
    pub pubkey_armored: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KemSealReport {
    pub algorithm: String,
    pub input: String,
    pub output: String,
    pub recipient_fingerprint: String,
    pub container_bytes: usize,
    pub armored: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KemOpenReport {
    pub input: String,
    pub output: String,
    pub plaintext_bytes: usize,
    pub verified: bool,
}

pub fn handle_kem_command(cmd: KemSubcommands) -> Result<()> {
    match cmd {
        KemSubcommands::Keygen(args) => handle_kem_keygen(args),
        KemSubcommands::Seal(args) => handle_kem_seal(args),
        KemSubcommands::Open(args) => handle_kem_open(args),
        KemSubcommands::Inspect(args) => handle_kem_inspect(args),
    }
}

pub fn handle_kem_keygen(args: KemKeygenArgs) -> Result<()> {
    let mut rng = rand::thread_rng();
    let keypair = HybridKeyPair::generate(&mut rng);
    let fingerprint = keypair.public_key.fingerprint();

    let pub_bytes = if args.armor {
        keypair.public_key.to_armored().into_bytes()
    } else {
        keypair.public_key.to_bytes()
    };

    let priv_bytes = if args.armor {
        keypair.private_key.to_armored().into_bytes()
    } else {
        keypair.private_key.to_bytes()
    };

    if let Some(ref path) = args.pubkey {
        fs::write(path, &pub_bytes)?;
    }
    if let Some(ref path) = args.privkey {
        fs::write(path, &priv_bytes)?;
    }

    if args.json {
        let report = KemKeygenReport {
            algorithm: "X25519 + ML-KEM-768 (FIPS 203)".into(),
            fingerprint: fingerprint.clone(),
            pubkey_file: args.pubkey.map(|p| p.display().to_string()),
            privkey_file: args.privkey.map(|p| p.display().to_string()),
            pubkey_armored: Some(keypair.public_key.to_armored()),
        };
        println!("{}", serde_json::to_string_pretty(&report).unwrap());
        return Ok(());
    }

    println!(
        "{}",
        "=== Post-Quantum Hybrid Keypair Generated ==="
            .bold()
            .green()
    );
    println!(
        "  Algorithm   : {}",
        "X25519 + ML-KEM-768 (FIPS 203)".cyan()
    );
    println!("  Fingerprint : {}", fingerprint.yellow());
    if let Some(ref p) = args.pubkey {
        println!("  Public Key  : {}", p.display());
    } else {
        println!("\n{}", keypair.public_key.to_armored());
    }
    if let Some(ref p) = args.privkey {
        println!("  Private Key : {}", p.display());
    }
    Ok(())
}

pub fn handle_kem_seal(args: KemSealArgs) -> Result<()> {
    let recipient_pk = resolve_public_key(&args.pubkey)?;
    let recipient_fp = recipient_pk.fingerprint();

    let bytes_written = seal_pq_vault(&args.input, &args.output, &recipient_pk, args.armor)?;

    if args.json {
        let report = KemSealReport {
            algorithm: "X25519 + ML-KEM-768 + ChaCha20-Poly1305".into(),
            input: args.input.display().to_string(),
            output: args.output.display().to_string(),
            recipient_fingerprint: recipient_fp,
            container_bytes: bytes_written,
            armored: args.armor,
        };
        println!("{}", serde_json::to_string_pretty(&report).unwrap());
        return Ok(());
    }

    println!(
        "{}",
        "=== Post-Quantum Vault Sealed Successfully ==="
            .bold()
            .green()
    );
    println!("  Input       : {}", args.input.display());
    println!("  Output      : {}", args.output.display());
    println!("  Recipient   : {}", recipient_fp.yellow());
    println!("  Size        : {} bytes", bytes_written);
    println!("  Armored     : {}", args.armor);
    Ok(())
}

pub fn handle_kem_open(args: KemOpenArgs) -> Result<()> {
    let recipient_sk = resolve_private_key(&args.privkey)?;
    let bytes_written = open_pq_vault(&args.input, &args.output, &recipient_sk)?;

    if args.json {
        let report = KemOpenReport {
            input: args.input.display().to_string(),
            output: args.output.display().to_string(),
            plaintext_bytes: bytes_written,
            verified: true,
        };
        println!("{}", serde_json::to_string_pretty(&report).unwrap());
        return Ok(());
    }

    println!(
        "{}",
        "=== Post-Quantum Vault Opened Successfully ==="
            .bold()
            .green()
    );
    println!("  Input       : {}", args.input.display());
    println!("  Output      : {}", args.output.display());
    println!("  Decrypted   : {} bytes", bytes_written);
    println!("  AEAD Auth   : {}", "VERIFIED (Poly1305 + CRC-32)".green());
    Ok(())
}

pub fn handle_kem_inspect(args: KemInspectArgs) -> Result<()> {
    let report = inspect_pq_vault(&args.input)?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&report).unwrap());
        return Ok(());
    }

    println!(
        "{}",
        "=== Post-Quantum Container Inspection ===".bold().cyan()
    );
    println!("  File             : {}", args.input.display());
    println!("  Format           : SVPQ v{}", report.version);
    println!("  Magic Valid      : {}", report.valid_magic);
    println!("  CRC-32 Valid     : {}", report.crc32_valid);
    println!("  Ephemeral X25519 : {}", report.ephemeral_x25519_pk_hex);
    println!("  ML-KEM-768 CT    : {} bytes", report.mlkem_ciphertext_len);
    println!("  Plaintext Size   : {} bytes", report.plaintext_len);
    println!(
        "  Total Container  : {} bytes",
        report.total_container_bytes
    );
    Ok(())
}

fn resolve_public_key(input: &str) -> Result<HybridPublicKey> {
    let path = Path::new(input);
    if path.exists() {
        let bytes = fs::read(path)?;
        HybridPublicKey::from_armored_or_raw(&bytes)
    } else {
        HybridPublicKey::from_armored_or_raw(input.as_bytes())
    }
}

fn resolve_private_key(input: &str) -> Result<HybridPrivateKey> {
    let path = Path::new(input);
    if path.exists() {
        let bytes = fs::read(path)?;
        HybridPrivateKey::from_armored_or_raw(&bytes)
    } else {
        HybridPrivateKey::from_armored_or_raw(input.as_bytes())
    }
}
