// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

mod cli;
mod crypto;
mod decoy;
mod error;
mod shred;
mod stego;
mod wav;

use anyhow::{Context, Result};
use clap::Parser;
use cli::{Cli, Commands};
use colored::Colorize;
use std::fs;

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Encrypt {
            input,
            output,
            passphrase,
            decoy,
            decoy_passphrase,
            padding,
            dpapi,
        } => {
            let raw = fs::read(&input)
                .with_context(|| format!("failed to read input file: {}", input.display()))?;
            let sealed = if let Some(decoy_path) = decoy {
                let d_pass = decoy_passphrase.ok_or_else(|| {
                    anyhow::anyhow!("--decoy-passphrase is required when --decoy is specified")
                })?;
                let raw_decoy = fs::read(&decoy_path).with_context(|| {
                    format!("failed to read decoy file: {}", decoy_path.display())
                })?;
                decoy::seal_decoy(&raw, &passphrase, &raw_decoy, &d_pass, dpapi, padding)?
            } else if padding > 0 {
                decoy::seal_v2(&raw, &passphrase, dpapi, padding)?
            } else {
                crypto::seal(&raw, &passphrase, dpapi)?
            };
            fs::write(&output, &sealed)
                .with_context(|| format!("failed to write container: {}", output.display()))?;
            println!(
                "{} encrypted {} bytes -> {} (dpapi={})",
                "ok".green().bold(),
                raw.len(),
                output.display(),
                dpapi
            );
        }
        Commands::EncryptDecoy {
            primary,
            decoy,
            output,
            passphrase,
            decoy_passphrase,
            padding,
            dpapi,
        } => {
            let raw_primary = fs::read(&primary)
                .with_context(|| format!("failed to read primary file: {}", primary.display()))?;
            let raw_decoy = fs::read(&decoy)
                .with_context(|| format!("failed to read decoy file: {}", decoy.display()))?;
            let sealed = decoy::seal_decoy(
                &raw_primary,
                &passphrase,
                &raw_decoy,
                &decoy_passphrase,
                dpapi,
                padding,
            )?;
            fs::write(&output, &sealed)
                .with_context(|| format!("failed to write container: {}", output.display()))?;
            println!(
                "{} encrypted dual-slot container (primary: {} bytes, decoy: {} bytes) -> {} (dpapi={})",
                "ok".green().bold(),
                raw_primary.len(),
                raw_decoy.len(),
                output.display(),
                dpapi
            );
        }
        Commands::Decrypt {
            input,
            output,
            passphrase,
            decoy_passphrase,
        }
        | Commands::DecryptDecoy {
            input,
            output,
            passphrase,
            decoy_passphrase,
        } => {
            let container = fs::read(&input)
                .with_context(|| format!("failed to read container: {}", input.display()))?;
            let plain = if let Some(d_pass) = decoy_passphrase {
                if crypto::is_decoy_container(&container) {
                    decoy::open_decoy_explicit(&container, passphrase.as_deref(), Some(&d_pass))?
                } else {
                    crypto::open(&container, &d_pass)?
                }
            } else if let Some(p) = passphrase {
                crypto::open(&container, &p)?
            } else {
                anyhow::bail!("either --passphrase or --decoy-passphrase must be provided");
            };
            fs::write(&output, &plain)
                .with_context(|| format!("failed to write output: {}", output.display()))?;
            println!(
                "{} decrypted {} bytes -> {}",
                "ok".green().bold(),
                plain.len(),
                output.display()
            );
        }
        Commands::Embed {
            carrier,
            secret,
            output,
            passphrase,
            decoy,
            decoy_passphrase,
            padding,
            dpapi,
        } => {
            let png = fs::read(&carrier)
                .with_context(|| format!("failed to read carrier PNG: {}", carrier.display()))?;
            let raw_secret = fs::read(&secret)
                .with_context(|| format!("failed to read secret file: {}", secret.display()))?;
            let sealed = if let Some(decoy_path) = decoy {
                let d_pass = decoy_passphrase.ok_or_else(|| {
                    anyhow::anyhow!("--decoy-passphrase is required when --decoy is specified")
                })?;
                let raw_decoy = fs::read(&decoy_path).with_context(|| {
                    format!("failed to read decoy file: {}", decoy_path.display())
                })?;
                decoy::seal_decoy(
                    &raw_secret,
                    &passphrase,
                    &raw_decoy,
                    &d_pass,
                    dpapi,
                    padding,
                )?
            } else if padding > 0 {
                decoy::seal_v2(&raw_secret, &passphrase, dpapi, padding)?
            } else {
                crypto::seal(&raw_secret, &passphrase, dpapi)?
            };
            let stego_png = stego::embed_in_png(&png, &sealed)?;
            fs::write(&output, &stego_png)
                .with_context(|| format!("failed to write stego PNG: {}", output.display()))?;
            println!(
                "{} embedded {} bytes into {}",
                "ok".green().bold(),
                raw_secret.len(),
                output.display()
            );
        }
        Commands::Extract {
            carrier,
            output,
            passphrase,
            decoy_passphrase,
        } => {
            let png = fs::read(&carrier)
                .with_context(|| format!("failed to read stego PNG: {}", carrier.display()))?;
            let sealed = stego::extract_from_png(&png)?;
            let plain = if let Some(d_pass) = decoy_passphrase {
                if crypto::is_decoy_container(&sealed) {
                    decoy::open_decoy_explicit(&sealed, passphrase.as_deref(), Some(&d_pass))?
                } else {
                    crypto::open(&sealed, &d_pass)?
                }
            } else if let Some(p) = passphrase {
                crypto::open(&sealed, &p)?
            } else {
                anyhow::bail!("either --passphrase or --decoy-passphrase must be provided");
            };
            fs::write(&output, &plain)
                .with_context(|| format!("failed to write extracted file: {}", output.display()))?;
            println!(
                "{} extracted {} bytes -> {}",
                "ok".green().bold(),
                plain.len(),
                output.display()
            );
        }
        Commands::EmbedWav {
            carrier,
            secret,
            output,
            passphrase,
            mode,
            lsb,
            decoy,
            decoy_passphrase,
            padding,
            dpapi,
        } => {
            let wav_bytes = fs::read(&carrier)
                .with_context(|| format!("failed to read carrier WAV: {}", carrier.display()))?;
            let raw_secret = fs::read(&secret)
                .with_context(|| format!("failed to read secret file: {}", secret.display()))?;
            let sealed = if let Some(decoy_path) = decoy {
                let d_pass = decoy_passphrase.ok_or_else(|| {
                    anyhow::anyhow!("--decoy-passphrase is required when --decoy is specified")
                })?;
                let raw_decoy = fs::read(&decoy_path).with_context(|| {
                    format!("failed to read decoy file: {}", decoy_path.display())
                })?;
                decoy::seal_decoy(
                    &raw_secret,
                    &passphrase,
                    &raw_decoy,
                    &d_pass,
                    dpapi,
                    padding,
                )?
            } else if padding > 0 {
                decoy::seal_v2(&raw_secret, &passphrase, dpapi, padding)?
            } else {
                crypto::seal(&raw_secret, &passphrase, dpapi)?
            };
            let effective_mode = if lsb { wav::WavMode::Lsb } else { mode };
            let stego_wav = wav::embed_in_wav(&wav_bytes, &sealed, effective_mode)?;
            fs::write(&output, &stego_wav)
                .with_context(|| format!("failed to write stego WAV: {}", output.display()))?;
            println!(
                "{} embedded {} bytes into {} (mode: {})",
                "ok".green().bold(),
                raw_secret.len(),
                output.display(),
                effective_mode
            );
        }
        Commands::ExtractWav {
            carrier,
            output,
            passphrase,
            decoy_passphrase,
            mode,
            lsb,
        } => {
            let wav_bytes = fs::read(&carrier)
                .with_context(|| format!("failed to read stego WAV: {}", carrier.display()))?;
            let effective_mode = if lsb { wav::ExtractWavMode::Lsb } else { mode };
            let sealed = wav::extract_from_wav(&wav_bytes, effective_mode)?;
            let plain = if let Some(d_pass) = decoy_passphrase {
                if crypto::is_decoy_container(&sealed) {
                    decoy::open_decoy_explicit(&sealed, passphrase.as_deref(), Some(&d_pass))?
                } else {
                    crypto::open(&sealed, &d_pass)?
                }
            } else if let Some(p) = passphrase {
                crypto::open(&sealed, &p)?
            } else {
                anyhow::bail!("either --passphrase or --decoy-passphrase must be provided");
            };
            fs::write(&output, &plain)
                .with_context(|| format!("failed to write extracted file: {}", output.display()))?;
            println!(
                "{} extracted {} bytes -> {}",
                "ok".green().bold(),
                plain.len(),
                output.display()
            );
        }
        Commands::Inspect { input } => {
            let raw = fs::read(&input)
                .with_context(|| format!("failed to read file: {}", input.display()))?;
            let container = if raw.starts_with(b"\x89PNG\r\n\x1a\n") {
                stego::extract_from_png(&raw)?
            } else if raw.len() >= 12 && &raw[0..4] == b"RIFF" && &raw[8..12] == b"WAVE" {
                wav::extract_from_wav(&raw, wav::ExtractWavMode::Auto)?
            } else {
                raw
            };
            let info = crypto::inspect(&container)?;
            println!("container_version: {}", info.version);
            println!("dpapi_bound:       {}", info.dpapi_bound);
            println!("payload_bytes:     {}", info.payload_size);
            println!("salt_hex:          {}", info.salt_hex);
            if info.decoy_container {
                println!("decoy_container:   true");
                println!("container_type:    decoy (plausible deniability)");
            }
        }
        Commands::Shred { input, passes } => {
            let wiped = shred::shred_file(&input, passes)?;
            println!(
                "{} shredded {} ({} bytes, {} passes)",
                "ok".green().bold(),
                input.display(),
                wiped,
                passes
            );
        }
    }

    Ok(())
}
