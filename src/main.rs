// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

mod audit;
mod cli;
mod clipboard_guard;
mod crypto;

mod decoy;
mod error;
mod shamir;
mod shred;
mod stego;
mod totp;
mod wav;

use anyhow::{Context, Result};
use clap::Parser;
use cli::{Cli, Commands, TotpAction};
use colored::Colorize;
use std::fs;
use std::io::{Read, Write};
use zeroize::Zeroize;

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
        Commands::Split {
            input,
            secret,
            threshold,
            shares,
            output_prefix,
            json,
            compact,
        } => {
            let secret_bytes = if let Some(path) = input {
                if path.to_str() == Some("-") {
                    let mut buf = Vec::new();
                    std::io::stdin()
                        .read_to_end(&mut buf)
                        .context("failed to read secret from stdin")?;
                    buf
                } else {
                    fs::read(&path).with_context(|| {
                        format!("failed to read secret file: {}", path.display())
                    })?
                }
            } else if let Some(s) = secret {
                s.into_bytes()
            } else {
                let mut buf = Vec::new();
                std::io::stdin()
                    .read_to_end(&mut buf)
                    .context("failed to read secret from stdin")?;
                buf
            };

            let share_objs = shamir::split_secret(&secret_bytes, threshold, shares)?;

            if let Some(prefix) = output_prefix {
                if let Some(parent) = prefix.parent() {
                    if !parent.as_os_str().is_empty() {
                        fs::create_dir_all(parent)?;
                    }
                }
                for s in &share_objs {
                    let file_name = format!("{}_{}.share", prefix.display(), s.index);
                    fs::write(&file_name, s.to_armored())
                        .with_context(|| format!("failed to write share file: {file_name}"))?;
                }
                println!(
                    "{} split {} bytes into {} shares (threshold: {}) with prefix {}",
                    "ok".green().bold(),
                    secret_bytes.len(),
                    shares,
                    threshold,
                    prefix.display()
                );
            } else if json {
                println!("{}", serde_json::to_string_pretty(&share_objs)?);
            } else if compact {
                for s in &share_objs {
                    println!("{}", s.to_compact());
                }
            } else {
                for (i, s) in share_objs.iter().enumerate() {
                    if i > 0 {
                        println!();
                    }
                    print!("{}", s.to_armored());
                }
            }
        }
        Commands::Combine {
            shares,
            output,
            raw,
            json,
        } => {
            let mut share_objs = Vec::new();
            if shares.is_empty() {
                let mut content = String::new();
                std::io::stdin()
                    .read_to_string(&mut content)
                    .context("failed to read shares from stdin")?;
                for block in content.split("-----END SHADOW VAULT SHARE-----") {
                    let trimmed = block.trim();
                    if trimmed.is_empty() {
                        continue;
                    }
                    let full_block = format!("{}\n-----END SHADOW VAULT SHARE-----", trimmed);
                    share_objs.push(shamir::Share::from_armored(&full_block)?);
                }
            } else {
                for item in &shares {
                    let path = std::path::Path::new(item);
                    if path.exists() {
                        let text = fs::read_to_string(path).with_context(|| {
                            format!("failed to read share file: {}", path.display())
                        })?;
                        share_objs.push(text.parse::<shamir::Share>()?);
                    } else {
                        share_objs.push(item.parse::<shamir::Share>()?);
                    }
                }
            }

            let recovered = shamir::combine_shares(&share_objs)?;

            if let Some(out_path) = output {
                fs::write(&out_path, &*recovered).with_context(|| {
                    format!("failed to write recovered file: {}", out_path.display())
                })?;
                println!(
                    "{} combined {} shares -> {} ({} bytes, hash: {})",
                    "ok".green().bold(),
                    share_objs.len(),
                    out_path.display(),
                    recovered.len(),
                    &share_objs[0].secret_hash[..8]
                );
            } else if json {
                let is_utf8 = std::str::from_utf8(&recovered).is_ok();
                let result = serde_json::json!({
                    "success": true,
                    "secret_len": recovered.len(),
                    "secret_hash": share_objs[0].secret_hash,
                    "secret_hex": recovered.iter().map(|b| format!("{b:02x}")).collect::<String>(),
                    "secret_utf8": if is_utf8 { std::str::from_utf8(&recovered).ok() } else { None },
                });
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else if raw {
                std::io::stdout()
                    .write_all(&recovered)
                    .context("failed to write raw secret to stdout")?;
            } else if let Ok(s) = std::str::from_utf8(&recovered) {
                print!("{s}");
                if !s.ends_with('\n') {
                    println!();
                }
            } else {
                std::io::stdout()
                    .write_all(&recovered)
                    .context("failed to write binary secret to stdout")?;
            }
        }
        Commands::Audit {
            target,
            mut passphrase,
            json,
        } => {
            let mut pass_report = None;
            let mut carrier_report = None;

            if let Some(target_path) = target {
                if target_path.to_str() == Some("-") {
                    let mut stdin_bytes = zeroize::Zeroizing::new(Vec::new());
                    std::io::stdin()
                        .read_to_end(&mut stdin_bytes)
                        .context("failed to read carrier data from stdin for audit")?;
                    if stdin_bytes.is_empty() {
                        anyhow::bail!("piped stdin for target '-' contains 0 bytes");
                    }
                    carrier_report = Some(audit::audit_carrier_bytes("<stdin>", &stdin_bytes)?);
                } else {
                    carrier_report = Some(audit::audit_file(&target_path)?);
                }
                if let Some(ref p) = passphrase {
                    pass_report = Some(audit::audit_passphrase(p));
                }
            } else if let Some(ref p) = passphrase {
                pass_report = Some(audit::audit_passphrase(p));
            } else {
                use std::io::IsTerminal;
                if std::io::stdin().is_terminal() {
                    anyhow::bail!(
                        "either TARGET file, --passphrase, or piped input must be provided for audit"
                    );
                }
                let mut raw_bytes = zeroize::Zeroizing::new(Vec::new());
                std::io::stdin()
                    .read_to_end(&mut raw_bytes)
                    .context("failed to read input from stdin for audit")?;
                if raw_bytes.is_empty() {
                    anyhow::bail!(
                        "either TARGET file, --passphrase, or piped input must be provided for audit"
                    );
                }

                // Discriminate between binary/container carriers and plaintext passphrases
                let is_known_carrier = raw_bytes.starts_with(b"\x89PNG\r\n\x1a\n")
                    || (raw_bytes.len() >= 12
                        && &raw_bytes[0..4] == b"RIFF"
                        && &raw_bytes[8..12] == b"WAVE")
                    || raw_bytes.starts_with(b"SVLT");

                if is_known_carrier
                    || raw_bytes.contains(&0)
                    || std::str::from_utf8(&raw_bytes).is_err()
                {
                    carrier_report = Some(audit::audit_carrier_bytes("<stdin>", &raw_bytes)?);
                } else {
                    let text = std::str::from_utf8(&raw_bytes).unwrap();
                    let trimmed = text.trim();
                    if trimmed.is_empty() {
                        anyhow::bail!(
                            "either TARGET file, --passphrase, or piped input must be provided for audit"
                        );
                    }
                    if trimmed.lines().count() <= 1 && trimmed.len() <= 256 {
                        pass_report = Some(audit::audit_passphrase(trimmed));
                    } else {
                        carrier_report = Some(audit::audit_carrier_bytes("<stdin>", &raw_bytes)?);
                    }
                }
            }

            // Proactively wipe passphrase string from memory
            if let Some(ref mut p) = passphrase {
                zeroize::Zeroize::zeroize(p);
            }

            if json {
                let combined = audit::CombinedAuditReport {
                    passphrase: pass_report,
                    carrier: carrier_report,
                };
                println!("{}", serde_json::to_string_pretty(&combined)?);
            } else {
                if let Some(ref rep) = pass_report {
                    print_passphrase_audit(rep);
                }
                if let Some(ref rep) = carrier_report {
                    if pass_report.is_some() {
                        println!();
                    }
                    print_carrier_audit(rep);
                }
            }
        }
        Commands::Totp { action } => {
            handle_totp_command(action)?;
        }
    }

    Ok(())
}

fn handle_totp_command(action: TotpAction) -> Result<()> {
    match action {
        TotpAction::Add {
            name,
            secret,
            uri,
            issuer,
            algorithm,
            digits,
            period,
            vault,
            mut passphrase,
            dpapi,
        } => {
            let record = if let Some(ref uri_str) = uri {
                let parsed = totp::OtpAuthUri::parse(uri_str)?;
                let rec_name = name.unwrap_or(parsed.account);
                let rec_issuer = issuer.or(parsed.issuer);
                let rec_secret = parsed.secret;
                let rec_algo = if algorithm != "SHA1" {
                    totp::HashAlgorithm::from_str_loose(&algorithm)?
                } else {
                    parsed.algorithm
                };
                let rec_digits = if digits != 6 { digits } else { parsed.digits };
                let rec_period = if period != 30 { period } else { parsed.period };
                totp::TotpRecord::new(
                    rec_name, rec_issuer, rec_secret, rec_algo, rec_digits, rec_period,
                )?
            } else if let Some(sec) = secret {
                let rec_name = name.ok_or_else(|| {
                    anyhow::anyhow!("account name is required when specifying --secret")
                })?;
                let rec_algo = totp::HashAlgorithm::from_str_loose(&algorithm)?;
                totp::TotpRecord::new(rec_name, issuer, sec, rec_algo, digits, period)?
            } else {
                anyhow::bail!("either --secret or --uri must be provided");
            };

            let mut vault_inst = totp::TotpVault::load_or_new(&vault, &passphrase)?;
            let bind_dpapi = dpapi || vault_inst.dpapi_bound;
            let record_name = record.name.clone();
            let record_algo = record.algorithm;
            let record_digits = record.digits;
            let record_period = record.period;

            vault_inst.add_record(record)?;
            vault_inst.save(&vault, &passphrase, bind_dpapi)?;
            passphrase.zeroize();

            println!(
                "{} added TOTP 2FA record '{}' to {} (algo={}, digits={}, period={}s, dpapi={})",
                "ok".green().bold(),
                record_name,
                vault.display(),
                record_algo,
                record_digits,
                record_period,
                bind_dpapi
            );
        }

        TotpAction::Code {
            name,
            time,
            vault,
            mut passphrase,
            json,
        } => {
            let vault_inst = totp::TotpVault::load(&vault, &passphrase)?;
            passphrase.zeroize();

            let record = vault_inst.get_record(&name).ok_or_else(|| {
                anyhow::anyhow!("record '{}' not found in vault {}", name, vault.display())
            })?;

            let timestamp = time.unwrap_or_else(|| {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0)
            });

            let (code, remaining) = vault_inst.generate_code(&name, timestamp)?;

            if json {
                let out = serde_json::json!({
                    "name": record.name,
                    "issuer": record.issuer,
                    "code": code,
                    "remaining_seconds": remaining,
                    "period": record.period,
                    "algorithm": record.algorithm.as_str(),
                    "digits": record.digits,
                    "timestamp": timestamp,
                });
                println!("{}", serde_json::to_string_pretty(&out)?);
            } else {
                let bar = totp::render_progress_bar(remaining, record.period, 10);
                let issuer_str = record
                    .issuer
                    .as_deref()
                    .map(|i| format!("{i} "))
                    .unwrap_or_default();
                println!(
                    "{} TOTP Code for {}{}: {} {} {}",
                    "ok".green().bold(),
                    issuer_str.bold(),
                    format!("({})", record.name).dimmed(),
                    code.cyan().bold(),
                    bar.yellow(),
                    format!("({}s remaining)", remaining).green()
                );
            }
        }

        TotpAction::List {
            vault,
            mut passphrase,
            json,
        } => {
            let vault_inst = totp::TotpVault::load(&vault, &passphrase)?;
            passphrase.zeroize();
            let records = vault_inst.list_records();

            if json {
                let summaries: Vec<_> = records
                    .iter()
                    .map(|r| {
                        serde_json::json!({
                            "name": r.name,
                            "issuer": r.issuer,
                            "algorithm": r.algorithm.as_str(),
                            "digits": r.digits,
                            "period": r.period,
                            "created_at": r.created_at,
                        })
                    })
                    .collect();
                println!("{}", serde_json::to_string_pretty(&summaries)?);
            } else {
                println!(
                    "{} TOTP 2FA Vault: {} ({} records, dpapi={})",
                    "=== [TOTP VAULT] ===".bold(),
                    vault.display(),
                    records.len(),
                    vault_inst.dpapi_bound
                );
                if records.is_empty() {
                    println!("  (no records stored)");
                } else {
                    println!(
                        "  {:<20} {:<15} {:<8} {:<8} {:<8}",
                        "ACCOUNT", "ISSUER", "ALGO", "DIGITS", "PERIOD"
                    );
                    println!("  {}", "-".repeat(65));
                    for r in records {
                        let iss = r.issuer.as_deref().unwrap_or("-");
                        println!(
                            "  {:<20} {:<15} {:<8} {:<8} {:<8}s",
                            r.name,
                            iss,
                            r.algorithm.as_str(),
                            r.digits,
                            r.period
                        );
                    }
                }
            }
        }

        TotpAction::Remove {
            name,
            vault,
            mut passphrase,
            dpapi,
        } => {
            let mut vault_inst = totp::TotpVault::load(&vault, &passphrase)?;
            let removed = vault_inst.remove_record(&name)?;
            let bind_dpapi = dpapi || vault_inst.dpapi_bound;
            vault_inst.save(&vault, &passphrase, bind_dpapi)?;
            passphrase.zeroize();

            println!(
                "{} removed TOTP record '{}' from {}",
                "ok".green().bold(),
                removed.name,
                vault.display()
            );
        }

        TotpAction::Verify {
            name,
            code,
            skew,
            time,
            vault,
            mut passphrase,
            json,
        } => {
            let vault_inst = totp::TotpVault::load(&vault, &passphrase)?;
            passphrase.zeroize();
            let record = vault_inst.get_record(&name).ok_or_else(|| {
                anyhow::anyhow!("record '{}' not found in vault {}", name, vault.display())
            })?;

            let timestamp = time.unwrap_or_else(|| {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0)
            });

            let is_valid = vault_inst.verify_code(&name, &code, timestamp, skew)?;

            if json {
                let out = serde_json::json!({
                    "name": record.name,
                    "issuer": record.issuer,
                    "code": code,
                    "valid": is_valid,
                    "timestamp": timestamp,
                    "skew": skew,
                });
                println!("{}", serde_json::to_string_pretty(&out)?);
                if !is_valid {
                    anyhow::bail!("TOTP verification failed: invalid code");
                }
            } else if is_valid {
                println!(
                    "{} TOTP code '{}' is VALID for '{}' (skew=\u{b1}{})",
                    "ok".green().bold(),
                    code,
                    record.name,
                    skew
                );
            } else {
                anyhow::bail!(
                    "TOTP verification failed: code '{}' is invalid for '{}'",
                    code,
                    record.name
                );
            }
        }

        TotpAction::Import {
            uri,
            file,
            vault,
            mut passphrase,
            dpapi,
        } => {
            let mut vault_inst = totp::TotpVault::load_or_new(&vault, &passphrase)?;
            let mut imported = 0usize;

            if let Some(ref uri_str) = uri {
                let parsed = totp::OtpAuthUri::parse(uri_str)?;
                let rec = totp::TotpRecord::new(
                    parsed.account,
                    parsed.issuer,
                    parsed.secret,
                    parsed.algorithm,
                    parsed.digits,
                    parsed.period,
                )?;
                vault_inst.add_record(rec)?;
                imported += 1;
            }

            if let Some(ref file_path) = file {
                let content = fs::read_to_string(file_path).with_context(|| {
                    format!("failed to read import file: {}", file_path.display())
                })?;
                for line in content.lines() {
                    let trimmed = line.trim();
                    if trimmed.is_empty() || trimmed.starts_with('#') {
                        continue;
                    }
                    if trimmed.starts_with("otpauth://") {
                        let parsed = totp::OtpAuthUri::parse(trimmed)?;
                        let rec = totp::TotpRecord::new(
                            parsed.account,
                            parsed.issuer,
                            parsed.secret,
                            parsed.algorithm,
                            parsed.digits,
                            parsed.period,
                        )?;
                        vault_inst.add_record(rec)?;
                        imported += 1;
                    }
                }
            }

            if imported == 0 {
                anyhow::bail!("no valid OTP records found to import (provide --uri or --file)");
            }

            let bind_dpapi = dpapi || vault_inst.dpapi_bound;
            vault_inst.save(&vault, &passphrase, bind_dpapi)?;
            passphrase.zeroize();

            println!(
                "{} imported {} record(s) into {}",
                "ok".green().bold(),
                imported,
                vault.display()
            );
        }

        TotpAction::Export {
            name,
            vault,
            mut passphrase,
            json,
        } => {
            let vault_inst = totp::TotpVault::load(&vault, &passphrase)?;
            passphrase.zeroize();

            if let Some(ref n) = name {
                let record = vault_inst.get_record(n).ok_or_else(|| {
                    anyhow::anyhow!("record '{}' not found in vault {}", n, vault.display())
                })?;
                let uri = record.to_uri();
                if json {
                    let out = serde_json::json!({
                        "name": record.name,
                        "issuer": record.issuer,
                        "uri": uri,
                    });
                    println!("{}", serde_json::to_string_pretty(&out)?);
                } else {
                    println!("{}", uri);
                }
            } else if json {
                let out: Vec<_> = vault_inst
                    .list_records()
                    .iter()
                    .map(|r| {
                        serde_json::json!({
                            "name": r.name,
                            "issuer": r.issuer,
                            "uri": r.to_uri(),
                        })
                    })
                    .collect();
                println!("{}", serde_json::to_string_pretty(&out)?);
            } else {
                for r in vault_inst.list_records() {
                    println!("{}", r.to_uri());
                }
            }
        }
    }

    Ok(())
}

fn print_passphrase_audit(rep: &audit::PassphraseAuditReport) {
    let strength_badge = match rep.strength {
        audit::StrengthLevel::VeryWeak => format!("[{}]", rep.strength).red().bold(),
        audit::StrengthLevel::Weak => format!("[{}]", rep.strength).yellow().bold(),
        audit::StrengthLevel::Moderate => format!("[{}]", rep.strength).cyan().bold(),
        audit::StrengthLevel::Strong => format!("[{}]", rep.strength).green().bold(),
        audit::StrengthLevel::VeryStrong => format!("[{}]", rep.strength).bright_green().bold(),
    };

    println!(
        "{} Passphrase Strength & Entropy Audit",
        "=== [AUDIT] ===".bold()
    );
    println!(
        "  Strength Rating:       {} (Score: {}/4)",
        strength_badge, rep.score
    );
    println!(
        "  Length:                {} characters ({} UTF-8 bytes)",
        rep.length_chars, rep.length_bytes
    );
    println!("  Character Pool Size:   {} possibilities", rep.pool_size);
    println!(
        "  Shannon Entropy:       {:.2} bits/byte (total: {:.1} bits)",
        rep.shannon_entropy_per_byte, rep.total_shannon_entropy_bits
    );
    println!("  Theoretical Pool Bits: {:.1} bits", rep.pool_entropy_bits);
    println!(
        "  Effective Entropy:     {:.1} bits",
        rep.effective_entropy_bits
    );
    println!("  Time to Crack Estimates:");
    println!(
        "    - Online (100 guess/s):      {}",
        rep.crack_time_online.cyan()
    );
    println!(
        "    - Offline Argon2id (1k/s):    {}",
        rep.crack_time_offline_argon2.cyan()
    );
    println!(
        "    - Offline GPU Hash (10B/s):   {}",
        rep.crack_time_offline_fast.cyan()
    );

    if !rep.findings.is_empty() {
        println!("  Findings & Anomalies:");
        for f in &rep.findings {
            println!("    - {}", f.yellow());
        }
    }

    if !rep.suggestions.is_empty() {
        println!("  Recommendations:");
        for s in &rep.suggestions {
            println!("    - {}", s.bright_blue());
        }
    }
}

fn print_carrier_audit(rep: &audit::FileAuditReport) {
    let verdict_badge = match rep.verdict {
        audit::CarrierVerdict::CleanCarrier => format!("[{}]", rep.verdict).green().bold(),
        audit::CarrierVerdict::StegoCarrierDetected => {
            format!("[{}]", rep.verdict).bright_yellow().bold()
        }
        audit::CarrierVerdict::SuspiciousAnomaly => format!("[{}]", rep.verdict).red().bold(),
        audit::CarrierVerdict::EncryptedContainer => {
            format!("[{}]", rep.verdict).bright_cyan().bold()
        }
        audit::CarrierVerdict::PlaintextFile => format!("[{}]", rep.verdict).yellow().bold(),
        audit::CarrierVerdict::BinaryData => format!("[{}]", rep.verdict).white().bold(),
    };

    println!(
        "{} Carrier Steganalysis & Integrity Audit",
        "=== [AUDIT] ===".bold()
    );
    println!("  Target Path:           {}", rep.file_path);
    println!("  File Size:             {} bytes", rep.file_size);
    println!("  Carrier Type:          {}", rep.carrier_type);
    println!(
        "  Shannon Entropy:       {:.4} bits/byte (max: 8.0)",
        rep.shannon_entropy
    );
    println!("  Chi-Square (df=255):   {:.2}", rep.chi_square);
    println!("  Steganalysis Verdict:  {}", verdict_badge);

    if let Some(v) = rep.details.container_version {
        println!("  Container Version:     v{}", v);
    }
    if let Some(dpapi) = rep.details.dpapi_bound {
        println!("  DPAPI Bound:           {}", dpapi);
    }
    if let Some(decoy) = rep.details.decoy_container {
        println!("  Decoy Container:       {}", decoy);
    }
    if let Some(bytes) = rep.details.payload_bytes {
        println!("  Payload Size:          {} bytes", bytes);
    }
    if rep.details.stego_chunk_present {
        println!("  Stego Chunk ('svLt'):  present (active)");
    }
    if rep.details.stego_lsb_present {
        println!("  Stego PCM LSB:         present (active)");
    }
    if rep.details.trailing_bytes > 0 {
        println!(
            "  Trailing Bytes:        {} bytes (post-EOF anomaly)",
            rep.details.trailing_bytes
        );
    }

    if !rep.findings.is_empty() {
        println!("  Findings:");
        for f in &rep.findings {
            println!("    - {}", f);
        }
    }

    if !rep.anomalies.is_empty() {
        println!("  Anomalies Detected:");
        for a in &rep.anomalies {
            println!("    - {}", a.red().bold());
        }
    }

    if !rep.recommendations.is_empty() {
        println!("  Recommendations:");
        for r in &rep.recommendations {
            println!("    - {}", r.bright_blue());
        }
    }
}
