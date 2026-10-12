// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

mod cli;
mod crypto;
mod error;
mod shred;
mod stego;

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
            dpapi,
        } => {
            let raw = fs::read(&input)
                .with_context(|| format!("failed to read input file: {}", input.display()))?;
            let sealed = crypto::seal(&raw, &passphrase, dpapi)?;
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
        Commands::Decrypt {
            input,
            output,
            passphrase,
        } => {
            let container = fs::read(&input)
                .with_context(|| format!("failed to read container: {}", input.display()))?;
            let plain = crypto::open(&container, &passphrase)?;
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
            dpapi,
        } => {
            let png = fs::read(&carrier)
                .with_context(|| format!("failed to read carrier PNG: {}", carrier.display()))?;
            let raw_secret = fs::read(&secret)
                .with_context(|| format!("failed to read secret file: {}", secret.display()))?;
            let sealed = crypto::seal(&raw_secret, &passphrase, dpapi)?;
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
        } => {
            let png = fs::read(&carrier)
                .with_context(|| format!("failed to read stego PNG: {}", carrier.display()))?;
            let sealed = stego::extract_from_png(&png)?;
            let plain = crypto::open(&sealed, &passphrase)?;
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
            } else {
                raw
            };
            let info = crypto::inspect(&container)?;
            println!("container_version: {}", info.version);
            println!("dpapi_bound:       {}", info.dpapi_bound);
            println!("payload_bytes:     {}", info.payload_size);
            println!("salt_hex:          {}", info.salt_hex);
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
