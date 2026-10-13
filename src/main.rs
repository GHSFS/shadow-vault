// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

mod archive;
mod armor;
mod audit;
mod bmp;
mod canary;
mod cli;
mod clipboard_guard;
mod crypto;
mod decoy;
mod diff;
mod error;
mod guard;
mod keyfile;
mod passgen;
mod policy;
mod rotate;
mod shamir;
mod shred;
mod stego;
mod stream;
mod totp;
mod wav;

use anyhow::{Context, Result};
use clap::Parser;
use cli::{
    CanaryAction, Cli, ClipAction, Commands, GuardAction, KeyfileAction, StreamAction, TotpAction,
};
use colored::Colorize;
use std::fs;
use std::io::{Read, Write};
use std::path::Path;
use zeroize::Zeroize;

fn parse_cli_policy(
    not_before: Option<&str>,
    expires_at: Option<&str>,
    expires_in: Option<&str>,
    policy_desc: Option<&str>,
) -> Result<Option<policy::PolicyHeader>> {
    let now = policy::current_utc_timestamp();
    let nb = if let Some(nb_str) = not_before {
        Some(policy::parse_timestamp_or_duration(nb_str, now)?)
    } else {
        None
    };

    let exp = if let Some(exp_str) = expires_at {
        Some(policy::parse_timestamp_or_duration(exp_str, now)?)
    } else if let Some(in_str) = expires_in {
        let dur = policy::parse_duration(in_str)?;
        Some(
            now.checked_add(dur)
                .ok_or_else(|| anyhow::anyhow!("expiration timestamp overflow"))?,
        )
    } else {
        None
    };

    if nb.is_none() && exp.is_none() && policy_desc.is_none() {
        return Ok(None);
    }

    let desc = policy_desc.map(|s| s.to_string());
    let pol = policy::PolicyHeader::new(nb, exp, desc)?;
    Ok(Some(pol))
}

fn parse_cli_at_time(at_time: Option<&str>) -> Result<Option<u64>> {
    match at_time {
        Some(s) => {
            let now = policy::current_utc_timestamp();
            let ts = policy::parse_timestamp_or_duration(s, now)?;
            Ok(Some(ts))
        }
        None => Ok(None),
    }
}

fn check_guard_preflight(target: &Path, at_time: Option<u64>) -> Result<()> {
    if let Some(guard_action) = guard::check_guard_before_attempt(target, at_time)? {
        match guard_action {
            guard::GuardAction::Allowed { remaining_attempts } => {
                if let Some(rem) = remaining_attempts {
                    if rem <= 2 {
                        eprintln!(
                            "{} Vault has {} attempt(s) remaining before self-destruction.",
                            "WARNING:".yellow().bold(),
                            rem
                        );
                    }
                }
            }
            guard::GuardAction::SelfShredTriggered {
                reason,
                target_path,
                ..
            } => {
                eprintln!(
                    "{} VAULT SELF-DESTRUCTION TRIGGERED: {:?} on {}",
                    "SECURITY ALERT:".red().bold(),
                    reason,
                    target_path.display()
                );
                anyhow::bail!(
                    "vault access refused: guard triggered self-destruction ({:?})",
                    reason
                );
            }
            guard::GuardAction::AttemptFailed { .. } => {}
        }
    }
    Ok(())
}

fn handle_guard_post_failure(target: &Path, at_time: Option<u64>) -> Result<()> {
    let action = guard::record_failure(target, at_time)?;
    match action {
        guard::GuardAction::SelfShredTriggered {
            reason,
            target_path,
            passes,
        } => {
            eprintln!(
                "{} MAXIMUM PASSPHRASE ATTEMPTS EXCEEDED — {} was permanently shredded ({} passes)",
                "CRITICAL SECURITY ALERT:".red().bold(),
                target_path.display(),
                passes
            );
            anyhow::bail!(
                "authentication failed: attempt limit reached, vault permanently shredded ({:?})",
                reason
            );
        }
        guard::GuardAction::AttemptFailed {
            failed_attempts,
            max_attempts,
            remaining,
        } => {
            eprintln!(
                "{} Authentication failed (attempt {}/{}). {} attempt(s) remaining before self-destruction.",
                "WARNING:".yellow().bold(),
                failed_attempts,
                max_attempts,
                remaining
            );
        }
        _ => {}
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn execute_standard_decrypt(
    input: std::path::PathBuf,
    output: Option<std::path::PathBuf>,
    passphrase: Option<String>,
    keyfile: Option<std::path::PathBuf>,
    decoy_passphrase: Option<String>,
    clip: bool,
    clip_ttl: u64,
    at_time: Option<String>,
    json: bool,
) -> Result<()> {
    let at_time_val = parse_cli_at_time(at_time.as_deref())?;
    check_guard_preflight(&input, at_time_val)?;

    let raw_container = fs::read(&input)
        .with_context(|| format!("failed to read container: {}", input.display()))?;
    let container = if armor::is_armored(&raw_container) {
        let text =
            std::str::from_utf8(&raw_container).context("armored container is not valid UTF-8")?;
        armor::dearmor_data(text)?.to_vec()
    } else {
        raw_container
    };

    let decrypt_result: Result<Vec<u8>> = (|| {
        if let Some(d_pass) = decoy_passphrase {
            if crypto::is_decoy_container(&container) {
                Ok(decoy::open_decoy_explicit_with_keyfile(
                    &container,
                    passphrase.as_deref(),
                    keyfile.as_deref(),
                    Some(&d_pass),
                )?)
            } else {
                Ok(crypto::open_at_with_keyfile(
                    &container,
                    Some(&d_pass),
                    keyfile.as_deref(),
                    at_time_val,
                )?)
            }
        } else if crypto::is_decoy_container(&container) {
            Ok(decoy::open_decoy_explicit_with_keyfile(
                &container,
                passphrase.as_deref(),
                keyfile.as_deref(),
                None,
            )?)
        } else if passphrase.is_some() || keyfile.is_some() {
            Ok(crypto::open_at_with_keyfile(
                &container,
                passphrase.as_deref(),
                keyfile.as_deref(),
                at_time_val,
            )?)
        } else {
            anyhow::bail!("either --passphrase, --keyfile, or --decoy-passphrase must be provided");
        }
    })();

    let mut plain = match decrypt_result {
        Ok(data) => {
            let _ = guard::record_success(&input, at_time_val);
            data
        }
        Err(err) => {
            handle_guard_post_failure(&input, at_time_val)?;
            return Err(err);
        }
    };
    if let Some(ref out_path) = output {
        fs::write(out_path, &plain)
            .with_context(|| format!("failed to write output: {}", out_path.display()))?;
        if json {
            let out = serde_json::json!({
                "status": "ok",
                "command": "decrypt",
                "input": input.display().to_string(),
                "output": out_path.display().to_string(),
                "plaintext_bytes": plain.len(),
                "clipboard_guarded": clip,
            });
            println!("{}", serde_json::to_string_pretty(&out)?);
        } else {
            println!(
                "{} decrypted {} bytes -> {}",
                "ok".green().bold(),
                plain.len(),
                out_path.display()
            );
        }
    } else if json {
        let is_utf8 = std::str::from_utf8(&plain).is_ok();
        let out = serde_json::json!({
            "status": "ok",
            "command": "decrypt",
            "input": input.display().to_string(),
            "output": null,
            "plaintext_bytes": plain.len(),
            "utf8_text": if is_utf8 { std::str::from_utf8(&plain).ok() } else { None },
            "clipboard_guarded": clip,
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else if !clip {
        anyhow::bail!("either --output, --clip, or --json must be provided");
    }
    if clip {
        match std::str::from_utf8(&plain) {
            Ok(text) => {
                let _ =
                    clipboard_guard::guard_interactive(text, clip_ttl, Some("decrypted vault"))?;
            }
            Err(_) => {
                use base64::Engine;
                let b64 = base64::engine::general_purpose::STANDARD.encode(&plain);
                let _ = clipboard_guard::guard_interactive(
                    &b64,
                    clip_ttl,
                    Some("decrypted binary (base64)"),
                )?;
            }
        }
    }
    plain.zeroize();
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Encrypt {
            input,
            output,
            passphrase,
            keyfile,
            decoy,
            decoy_passphrase,
            padding,
            dpapi,
            not_before,
            expires_at,
            expires_in,
            policy_desc,
            stream,
            chunk_size,
            max_attempts,
            dead_man,
            guard_companion,
            json,
        } => {
            let policy = parse_cli_policy(
                not_before.as_deref(),
                expires_at.as_deref(),
                expires_in.as_deref(),
                policy_desc.as_deref(),
            )?;
            let parsed_chunk_size = match chunk_size {
                Some(ref cs) => Some(stream::parse_chunk_size(cs)?),
                None => None,
            };
            if stream || parsed_chunk_size.is_some() {
                if decoy.is_some() || padding > 0 {
                    anyhow::bail!(
                        "streaming encryption cannot be combined with --decoy or --padding"
                    );
                }
                let summary = stream::encrypt_file_stream(
                    &input,
                    &output,
                    passphrase.as_deref(),
                    keyfile.as_deref(),
                    dpapi,
                    policy.as_ref(),
                    parsed_chunk_size,
                )?;
                if json {
                    let out = serde_json::json!({
                        "status": "ok",
                        "command": "encrypt",
                        "input": input.display().to_string(),
                        "output": output.display().to_string(),
                        "plaintext_bytes": summary.total_plaintext_bytes,
                        "chunks": summary.total_chunks,
                        "chunk_size": summary.chunk_size,
                        "dpapi_bound": dpapi,
                        "stream": true,
                    });
                    println!("{}", serde_json::to_string_pretty(&out)?);
                } else {
                    let policy_msg = match policy {
                        Some(ref p) => format!(
                            " policy={}",
                            p.status_summary(policy::current_utc_timestamp())
                        ),
                        None => String::new(),
                    };
                    println!(
                        "{} encrypted {} bytes in {} chunks -> {} (chunk_size: {} bytes, dpapi={}{})",
                        "ok".green().bold(),
                        summary.total_plaintext_bytes,
                        summary.total_chunks,
                        output.display(),
                        summary.chunk_size,
                        dpapi,
                        policy_msg
                    );
                }
                return Ok(());
            }
            let raw = fs::read(&input)
                .with_context(|| format!("failed to read input file: {}", input.display()))?;
            let sealed = if let Some(decoy_path) = decoy {
                let d_pass = decoy_passphrase.ok_or_else(|| {
                    anyhow::anyhow!("--decoy-passphrase is required when --decoy is specified")
                })?;
                let raw_decoy = fs::read(&decoy_path).with_context(|| {
                    format!("failed to read decoy file: {}", decoy_path.display())
                })?;
                decoy::seal_decoy_with_keyfile(
                    &raw,
                    passphrase.as_deref(),
                    keyfile.as_deref(),
                    &raw_decoy,
                    &d_pass,
                    dpapi,
                    padding,
                )?
            } else if padding > 0 {
                decoy::seal_v2_with_keyfile(
                    &raw,
                    passphrase.as_deref(),
                    keyfile.as_deref(),
                    dpapi,
                    padding,
                )?
            } else {
                crypto::seal_with_policy_and_keyfile(
                    &raw,
                    passphrase.as_deref(),
                    keyfile.as_deref(),
                    dpapi,
                    policy.as_ref(),
                )?
            };
            fs::write(&output, &sealed)
                .with_context(|| format!("failed to write container: {}", output.display()))?;
            let guard_info = if max_attempts.is_some() || dead_man.is_some() {
                let k = max_attempts.unwrap_or(3);
                let dead_man_seconds = match dead_man {
                    Some(ref dm) => Some(policy::parse_duration(dm)?),
                    None => None,
                };
                let g = guard::arm_guard(
                    &output,
                    k,
                    dead_man_seconds,
                    None,
                    guard::DEFAULT_SHRED_PASSES,
                    guard_companion,
                    None,
                )?;
                if !json {
                    let dm_str = g
                        .dead_man_interval_seconds
                        .map(|s| format!(" (dead-man: {s}s)"))
                        .unwrap_or_default();
                    println!(
                        "{} armed guard for {} (max_attempts={}{}, companion={})",
                        "ok".green().bold(),
                        output.display(),
                        g.max_attempts,
                        dm_str,
                        g.companion
                    );
                }
                Some(g)
            } else {
                None
            };
            if json {
                let out = serde_json::json!({
                    "status": "ok",
                    "command": "encrypt",
                    "input": input.display().to_string(),
                    "output": output.display().to_string(),
                    "plaintext_bytes": raw.len(),
                    "ciphertext_bytes": sealed.len(),
                    "dpapi_bound": dpapi,
                    "version": sealed.get(4).copied().unwrap_or(1),
                    "stream": false,
                    "guard_armed": guard_info.is_some(),
                });
                println!("{}", serde_json::to_string_pretty(&out)?);
            } else {
                let policy_msg = match policy {
                    Some(ref p) => format!(
                        " policy={}",
                        p.status_summary(policy::current_utc_timestamp())
                    ),
                    None => String::new(),
                };
                println!(
                    "{} encrypted {} bytes -> {} (dpapi={}{})",
                    "ok".green().bold(),
                    raw.len(),
                    output.display(),
                    dpapi,
                    policy_msg
                );
            }
        }
        Commands::EncryptDecoy {
            primary,
            decoy,
            output,
            passphrase,
            keyfile,
            decoy_passphrase,
            padding,
            dpapi,
            json,
        } => {
            let raw_primary = fs::read(&primary)
                .with_context(|| format!("failed to read primary file: {}", primary.display()))?;
            let raw_decoy = fs::read(&decoy)
                .with_context(|| format!("failed to read decoy file: {}", decoy.display()))?;
            let sealed = decoy::seal_decoy_with_keyfile(
                &raw_primary,
                Some(&passphrase),
                keyfile.as_deref(),
                &raw_decoy,
                &decoy_passphrase,
                dpapi,
                padding,
            )?;
            fs::write(&output, &sealed)
                .with_context(|| format!("failed to write container: {}", output.display()))?;
            if json {
                let out = serde_json::json!({
                    "status": "ok",
                    "command": "encrypt-decoy",
                    "primary": primary.display().to_string(),
                    "decoy": decoy.display().to_string(),
                    "output": output.display().to_string(),
                    "primary_bytes": raw_primary.len(),
                    "decoy_bytes": raw_decoy.len(),
                    "ciphertext_bytes": sealed.len(),
                    "dpapi_bound": dpapi,
                });
                println!("{}", serde_json::to_string_pretty(&out)?);
            } else {
                println!(
                    "{} encrypted dual-slot container (primary: {} bytes, decoy: {} bytes) -> {} (dpapi={})",
                    "ok".green().bold(),
                    raw_primary.len(),
                    raw_decoy.len(),
                    output.display(),
                    dpapi
                );
            }
        }
        Commands::Decrypt {
            input,
            output,
            passphrase,
            keyfile,
            decoy_passphrase,
            clip,
            clip_ttl,
            at_time,
            stream,
            json,
        } => {
            let is_stream = stream || {
                if let Ok(mut f) = fs::File::open(&input) {
                    let mut magic = [0u8; 4];
                    f.read_exact(&mut magic).is_ok() && &magic == stream::MAGIC
                } else {
                    false
                }
            };
            if is_stream {
                let out_path = output.as_ref().ok_or_else(|| {
                    anyhow::anyhow!("--output is required for streaming decryption")
                })?;
                let at_time_val = parse_cli_at_time(at_time.as_deref())?;
                check_guard_preflight(&input, at_time_val)?;
                let res = stream::decrypt_file_stream(
                    &input,
                    out_path,
                    passphrase.as_deref(),
                    keyfile.as_deref(),
                    at_time_val,
                );
                let summary = match res {
                    Ok(s) => {
                        let _ = guard::record_success(&input, at_time_val);
                        s
                    }
                    Err(e) => {
                        handle_guard_post_failure(&input, at_time_val)?;
                        return Err(e.into());
                    }
                };
                if json {
                    let out = serde_json::json!({
                        "status": "ok",
                        "command": "decrypt",
                        "input": input.display().to_string(),
                        "output": out_path.display().to_string(),
                        "plaintext_bytes": summary.total_plaintext_bytes,
                        "chunks": summary.total_chunks,
                        "stream": true,
                    });
                    println!("{}", serde_json::to_string_pretty(&out)?);
                } else {
                    println!(
                        "{} decrypted {} bytes in {} chunks -> {}",
                        "ok".green().bold(),
                        summary.total_plaintext_bytes,
                        summary.total_chunks,
                        out_path.display()
                    );
                }
                return Ok(());
            }

            execute_standard_decrypt(
                input,
                output,
                passphrase,
                keyfile,
                decoy_passphrase,
                clip,
                clip_ttl,
                at_time,
                json,
            )?;
        }
        Commands::DecryptDecoy {
            input,
            output,
            passphrase,
            keyfile,
            decoy_passphrase,
            clip,
            clip_ttl,
            at_time,
            json,
        } => {
            execute_standard_decrypt(
                input,
                output,
                passphrase,
                keyfile,
                decoy_passphrase,
                clip,
                clip_ttl,
                at_time,
                json,
            )?;
        }

        Commands::Embed {
            carrier,
            secret,
            output,
            passphrase,
            keyfile,
            decoy,
            decoy_passphrase,
            padding,
            dpapi,
            not_before,
            expires_at,
            expires_in,
            policy_desc,
            json,
        } => {
            let png = fs::read(&carrier)
                .with_context(|| format!("failed to read carrier PNG: {}", carrier.display()))?;
            let raw_secret = fs::read(&secret)
                .with_context(|| format!("failed to read secret file: {}", secret.display()))?;
            let policy = parse_cli_policy(
                not_before.as_deref(),
                expires_at.as_deref(),
                expires_in.as_deref(),
                policy_desc.as_deref(),
            )?;
            let sealed = if let Some(decoy_path) = decoy {
                let d_pass = decoy_passphrase.ok_or_else(|| {
                    anyhow::anyhow!("--decoy-passphrase is required when --decoy is specified")
                })?;
                let raw_decoy = fs::read(&decoy_path).with_context(|| {
                    format!("failed to read decoy file: {}", decoy_path.display())
                })?;
                decoy::seal_decoy_with_keyfile(
                    &raw_secret,
                    passphrase.as_deref(),
                    keyfile.as_deref(),
                    &raw_decoy,
                    &d_pass,
                    dpapi,
                    padding,
                )?
            } else if padding > 0 {
                decoy::seal_v2_with_keyfile(
                    &raw_secret,
                    passphrase.as_deref(),
                    keyfile.as_deref(),
                    dpapi,
                    padding,
                )?
            } else {
                crypto::seal_with_policy_and_keyfile(
                    &raw_secret,
                    passphrase.as_deref(),
                    keyfile.as_deref(),
                    dpapi,
                    policy.as_ref(),
                )?
            };
            let stego_png = stego::embed_in_png(&png, &sealed)?;
            fs::write(&output, &stego_png)
                .with_context(|| format!("failed to write stego PNG: {}", output.display()))?;
            if json {
                let out = serde_json::json!({
                    "status": "ok",
                    "command": "embed",
                    "carrier": carrier.display().to_string(),
                    "secret": secret.display().to_string(),
                    "output": output.display().to_string(),
                    "secret_bytes": raw_secret.len(),
                    "stego_bytes": stego_png.len(),
                    "carrier_type": "png",
                });
                println!("{}", serde_json::to_string_pretty(&out)?);
            } else {
                println!(
                    "{} embedded {} bytes into {}",
                    "ok".green().bold(),
                    raw_secret.len(),
                    output.display()
                );
            }
        }
        Commands::Extract {
            carrier,
            output,
            passphrase,
            keyfile,
            decoy_passphrase,
            clip,
            clip_ttl,
            at_time,
            json,
        } => {
            let png = fs::read(&carrier)
                .with_context(|| format!("failed to read stego PNG: {}", carrier.display()))?;
            let at_time_val = parse_cli_at_time(at_time.as_deref())?;
            check_guard_preflight(&carrier, at_time_val)?;

            let extract_res: Result<Vec<u8>> = (|| {
                let sealed = stego::extract_from_png(&png)?;
                if let Some(d_pass) = decoy_passphrase {
                    if crypto::is_decoy_container(&sealed) {
                        Ok(decoy::open_decoy_explicit_with_keyfile(
                            &sealed,
                            passphrase.as_deref(),
                            keyfile.as_deref(),
                            Some(&d_pass),
                        )?)
                    } else {
                        Ok(crypto::open_at_with_keyfile(
                            &sealed,
                            Some(&d_pass),
                            keyfile.as_deref(),
                            at_time_val,
                        )?)
                    }
                } else if crypto::is_decoy_container(&sealed) {
                    Ok(decoy::open_decoy_explicit_with_keyfile(
                        &sealed,
                        passphrase.as_deref(),
                        keyfile.as_deref(),
                        None,
                    )?)
                } else if passphrase.is_some() || keyfile.is_some() {
                    Ok(crypto::open_at_with_keyfile(
                        &sealed,
                        passphrase.as_deref(),
                        keyfile.as_deref(),
                        at_time_val,
                    )?)
                } else {
                    anyhow::bail!(
                        "either --passphrase, --keyfile, or --decoy-passphrase must be provided"
                    );
                }
            })();

            let mut plain = match extract_res {
                Ok(data) => {
                    let _ = guard::record_success(&carrier, at_time_val);
                    data
                }
                Err(err) => {
                    handle_guard_post_failure(&carrier, at_time_val)?;
                    return Err(err);
                }
            };
            if let Some(ref out_path) = output {
                fs::write(out_path, &plain).with_context(|| {
                    format!("failed to write extracted file: {}", out_path.display())
                })?;
                if json {
                    let out = serde_json::json!({
                        "status": "ok",
                        "command": "extract",
                        "carrier": carrier.display().to_string(),
                        "output": out_path.display().to_string(),
                        "extracted_bytes": plain.len(),
                        "carrier_type": "png",
                        "clipboard_guarded": clip,
                    });
                    println!("{}", serde_json::to_string_pretty(&out)?);
                } else {
                    println!(
                        "{} extracted {} bytes -> {}",
                        "ok".green().bold(),
                        plain.len(),
                        out_path.display()
                    );
                }
            } else if json {
                let is_utf8 = std::str::from_utf8(&plain).is_ok();
                let out = serde_json::json!({
                    "status": "ok",
                    "command": "extract",
                    "carrier": carrier.display().to_string(),
                    "output": null,
                    "extracted_bytes": plain.len(),
                    "utf8_text": if is_utf8 { std::str::from_utf8(&plain).ok() } else { None },
                    "carrier_type": "png",
                    "clipboard_guarded": clip,
                });
                println!("{}", serde_json::to_string_pretty(&out)?);
            } else if !clip {
                anyhow::bail!("either --output, --clip, or --json must be provided");
            }
            if clip {
                match std::str::from_utf8(&plain) {
                    Ok(text) => {
                        let _ = clipboard_guard::guard_interactive(
                            text,
                            clip_ttl,
                            Some("extracted secret"),
                        )?;
                    }
                    Err(_) => {
                        use base64::Engine;
                        let b64 = base64::engine::general_purpose::STANDARD.encode(&plain);
                        let _ = clipboard_guard::guard_interactive(
                            &b64,
                            clip_ttl,
                            Some("extracted binary (base64)"),
                        )?;
                    }
                }
            }
            plain.zeroize();
        }

        Commands::EmbedWav {
            carrier,
            secret,
            output,
            passphrase,
            keyfile,
            mode,
            lsb,
            decoy,
            decoy_passphrase,
            padding,
            dpapi,
            not_before,
            expires_at,
            expires_in,
            policy_desc,
            json,
        } => {
            let wav_bytes = fs::read(&carrier)
                .with_context(|| format!("failed to read carrier WAV: {}", carrier.display()))?;
            let raw_secret = fs::read(&secret)
                .with_context(|| format!("failed to read secret file: {}", secret.display()))?;
            let policy = parse_cli_policy(
                not_before.as_deref(),
                expires_at.as_deref(),
                expires_in.as_deref(),
                policy_desc.as_deref(),
            )?;
            let sealed = if let Some(decoy_path) = decoy {
                let d_pass = decoy_passphrase.ok_or_else(|| {
                    anyhow::anyhow!("--decoy-passphrase is required when --decoy is specified")
                })?;
                let raw_decoy = fs::read(&decoy_path).with_context(|| {
                    format!("failed to read decoy file: {}", decoy_path.display())
                })?;
                decoy::seal_decoy_with_keyfile(
                    &raw_secret,
                    passphrase.as_deref(),
                    keyfile.as_deref(),
                    &raw_decoy,
                    &d_pass,
                    dpapi,
                    padding,
                )?
            } else if padding > 0 {
                decoy::seal_v2_with_keyfile(
                    &raw_secret,
                    passphrase.as_deref(),
                    keyfile.as_deref(),
                    dpapi,
                    padding,
                )?
            } else {
                crypto::seal_with_policy_and_keyfile(
                    &raw_secret,
                    passphrase.as_deref(),
                    keyfile.as_deref(),
                    dpapi,
                    policy.as_ref(),
                )?
            };
            let effective_mode = if lsb { wav::WavMode::Lsb } else { mode };
            let stego_wav = wav::embed_in_wav(&wav_bytes, &sealed, effective_mode)?;
            fs::write(&output, &stego_wav)
                .with_context(|| format!("failed to write stego WAV: {}", output.display()))?;
            if json {
                let out = serde_json::json!({
                    "status": "ok",
                    "command": "embed-wav",
                    "carrier": carrier.display().to_string(),
                    "secret": secret.display().to_string(),
                    "output": output.display().to_string(),
                    "secret_bytes": raw_secret.len(),
                    "stego_bytes": stego_wav.len(),
                    "carrier_type": "wav",
                    "mode": effective_mode.to_string(),
                });
                println!("{}", serde_json::to_string_pretty(&out)?);
            } else {
                println!(
                    "{} embedded {} bytes into {} (mode: {})",
                    "ok".green().bold(),
                    raw_secret.len(),
                    output.display(),
                    effective_mode
                );
            }
        }
        Commands::ExtractWav {
            carrier,
            output,
            passphrase,
            keyfile,
            decoy_passphrase,
            mode,
            lsb,
            clip,
            clip_ttl,
            at_time,
            json,
        } => {
            let wav_bytes = fs::read(&carrier)
                .with_context(|| format!("failed to read stego WAV: {}", carrier.display()))?;
            let at_time_val = parse_cli_at_time(at_time.as_deref())?;
            check_guard_preflight(&carrier, at_time_val)?;

            let extract_res: Result<Vec<u8>> = (|| {
                let effective_mode = if lsb { wav::ExtractWavMode::Lsb } else { mode };
                let sealed = wav::extract_from_wav(&wav_bytes, effective_mode)?;
                if let Some(d_pass) = decoy_passphrase {
                    if crypto::is_decoy_container(&sealed) {
                        Ok(decoy::open_decoy_explicit_with_keyfile(
                            &sealed,
                            passphrase.as_deref(),
                            keyfile.as_deref(),
                            Some(&d_pass),
                        )?)
                    } else {
                        Ok(crypto::open_at_with_keyfile(
                            &sealed,
                            Some(&d_pass),
                            keyfile.as_deref(),
                            at_time_val,
                        )?)
                    }
                } else if crypto::is_decoy_container(&sealed) {
                    Ok(decoy::open_decoy_explicit_with_keyfile(
                        &sealed,
                        passphrase.as_deref(),
                        keyfile.as_deref(),
                        None,
                    )?)
                } else if passphrase.is_some() || keyfile.is_some() {
                    Ok(crypto::open_at_with_keyfile(
                        &sealed,
                        passphrase.as_deref(),
                        keyfile.as_deref(),
                        at_time_val,
                    )?)
                } else {
                    anyhow::bail!(
                        "either --passphrase, --keyfile, or --decoy-passphrase must be provided"
                    );
                }
            })();

            let mut plain = match extract_res {
                Ok(data) => {
                    let _ = guard::record_success(&carrier, at_time_val);
                    data
                }
                Err(err) => {
                    handle_guard_post_failure(&carrier, at_time_val)?;
                    return Err(err);
                }
            };
            if let Some(ref out_path) = output {
                fs::write(out_path, &plain).with_context(|| {
                    format!("failed to write extracted file: {}", out_path.display())
                })?;
                if json {
                    let out = serde_json::json!({
                        "status": "ok",
                        "command": "extract-wav",
                        "carrier": carrier.display().to_string(),
                        "output": out_path.display().to_string(),
                        "extracted_bytes": plain.len(),
                        "carrier_type": "wav",
                        "mode": (if lsb { wav::ExtractWavMode::Lsb } else { mode }).to_string(),
                        "clipboard_guarded": clip,
                    });
                    println!("{}", serde_json::to_string_pretty(&out)?);
                } else {
                    println!(
                        "{} extracted {} bytes -> {}",
                        "ok".green().bold(),
                        plain.len(),
                        out_path.display()
                    );
                }
            } else if json {
                let is_utf8 = std::str::from_utf8(&plain).is_ok();
                let out = serde_json::json!({
                    "status": "ok",
                    "command": "extract-wav",
                    "carrier": carrier.display().to_string(),
                    "output": null,
                    "extracted_bytes": plain.len(),
                    "utf8_text": if is_utf8 { std::str::from_utf8(&plain).ok() } else { None },
                    "carrier_type": "wav",
                    "mode": (if lsb { wav::ExtractWavMode::Lsb } else { mode }).to_string(),
                    "clipboard_guarded": clip,
                });
                println!("{}", serde_json::to_string_pretty(&out)?);
            } else if !clip {
                anyhow::bail!("either --output, --clip, or --json must be provided");
            }
            if clip {
                match std::str::from_utf8(&plain) {
                    Ok(text) => {
                        let _ = clipboard_guard::guard_interactive(
                            text,
                            clip_ttl,
                            Some("extracted secret"),
                        )?;
                    }
                    Err(_) => {
                        use base64::Engine;
                        let b64 = base64::engine::general_purpose::STANDARD.encode(&plain);
                        let _ = clipboard_guard::guard_interactive(
                            &b64,
                            clip_ttl,
                            Some("extracted binary (base64)"),
                        )?;
                    }
                }
            }
            plain.zeroize();
        }

        Commands::EmbedBmp {
            carrier,
            secret,
            output,
            passphrase,
            keyfile,
            decoy,
            decoy_passphrase,
            padding,
            dpapi,
            not_before,
            expires_at,
            expires_in,
            policy_desc,
            json,
        } => {
            let bmp_bytes = fs::read(&carrier)
                .with_context(|| format!("failed to read carrier BMP: {}", carrier.display()))?;
            let raw_secret = fs::read(&secret)
                .with_context(|| format!("failed to read secret file: {}", secret.display()))?;
            let policy = parse_cli_policy(
                not_before.as_deref(),
                expires_at.as_deref(),
                expires_in.as_deref(),
                policy_desc.as_deref(),
            )?;
            let sealed = if let Some(decoy_path) = decoy {
                let d_pass = decoy_passphrase.ok_or_else(|| {
                    anyhow::anyhow!("--decoy-passphrase is required when --decoy is specified")
                })?;
                let raw_decoy = fs::read(&decoy_path).with_context(|| {
                    format!("failed to read decoy file: {}", decoy_path.display())
                })?;
                decoy::seal_decoy_with_keyfile(
                    &raw_secret,
                    passphrase.as_deref(),
                    keyfile.as_deref(),
                    &raw_decoy,
                    &d_pass,
                    dpapi,
                    padding,
                )?
            } else if padding > 0 {
                decoy::seal_v2_with_keyfile(
                    &raw_secret,
                    passphrase.as_deref(),
                    keyfile.as_deref(),
                    dpapi,
                    padding,
                )?
            } else {
                crypto::seal_with_policy_and_keyfile(
                    &raw_secret,
                    passphrase.as_deref(),
                    keyfile.as_deref(),
                    dpapi,
                    policy.as_ref(),
                )?
            };
            let stego_bmp = bmp::embed_in_bmp(&bmp_bytes, &sealed)?;
            fs::write(&output, &stego_bmp)
                .with_context(|| format!("failed to write stego BMP: {}", output.display()))?;
            if json {
                let out = serde_json::json!({
                    "status": "ok",
                    "command": "embed-bmp",
                    "carrier": carrier.display().to_string(),
                    "secret": secret.display().to_string(),
                    "output": output.display().to_string(),
                    "secret_bytes": raw_secret.len(),
                    "stego_bytes": stego_bmp.len(),
                    "carrier_type": "bmp",
                });
                println!("{}", serde_json::to_string_pretty(&out)?);
            } else {
                println!(
                    "{} embedded {} bytes into {}",
                    "ok".green().bold(),
                    raw_secret.len(),
                    output.display()
                );
            }
        }
        Commands::ExtractBmp {
            carrier,
            output,
            passphrase,
            keyfile,
            decoy_passphrase,
            clip,
            clip_ttl,
            at_time,
            json,
        } => {
            let bmp_bytes = fs::read(&carrier)
                .with_context(|| format!("failed to read stego BMP: {}", carrier.display()))?;
            let at_time_val = parse_cli_at_time(at_time.as_deref())?;
            check_guard_preflight(&carrier, at_time_val)?;

            let extract_res: Result<Vec<u8>> = (|| {
                let sealed = bmp::extract_from_bmp(&bmp_bytes)?;
                if let Some(d_pass) = decoy_passphrase {
                    if crypto::is_decoy_container(&sealed) {
                        Ok(decoy::open_decoy_explicit_with_keyfile(
                            &sealed,
                            passphrase.as_deref(),
                            keyfile.as_deref(),
                            Some(&d_pass),
                        )?)
                    } else {
                        Ok(crypto::open_at_with_keyfile(
                            &sealed,
                            Some(&d_pass),
                            keyfile.as_deref(),
                            at_time_val,
                        )?)
                    }
                } else if crypto::is_decoy_container(&sealed) {
                    Ok(decoy::open_decoy_explicit_with_keyfile(
                        &sealed,
                        passphrase.as_deref(),
                        keyfile.as_deref(),
                        None,
                    )?)
                } else if passphrase.is_some() || keyfile.is_some() {
                    Ok(crypto::open_at_with_keyfile(
                        &sealed,
                        passphrase.as_deref(),
                        keyfile.as_deref(),
                        at_time_val,
                    )?)
                } else {
                    anyhow::bail!(
                        "either --passphrase, --keyfile, or --decoy-passphrase must be provided"
                    );
                }
            })();

            let mut plain = match extract_res {
                Ok(data) => {
                    let _ = guard::record_success(&carrier, at_time_val);
                    data
                }
                Err(err) => {
                    handle_guard_post_failure(&carrier, at_time_val)?;
                    return Err(err);
                }
            };
            if let Some(ref out_path) = output {
                fs::write(out_path, &plain).with_context(|| {
                    format!("failed to write extracted file: {}", out_path.display())
                })?;
                if json {
                    let out = serde_json::json!({
                        "status": "ok",
                        "command": "extract-bmp",
                        "carrier": carrier.display().to_string(),
                        "output": out_path.display().to_string(),
                        "extracted_bytes": plain.len(),
                        "carrier_type": "bmp",
                        "clipboard_guarded": clip,
                    });
                    println!("{}", serde_json::to_string_pretty(&out)?);
                } else {
                    println!(
                        "{} extracted {} bytes -> {}",
                        "ok".green().bold(),
                        plain.len(),
                        out_path.display()
                    );
                }
            } else if json {
                let is_utf8 = std::str::from_utf8(&plain).is_ok();
                let out = serde_json::json!({
                    "status": "ok",
                    "command": "extract-bmp",
                    "carrier": carrier.display().to_string(),
                    "output": null,
                    "extracted_bytes": plain.len(),
                    "utf8_text": if is_utf8 { std::str::from_utf8(&plain).ok() } else { None },
                    "carrier_type": "bmp",
                    "clipboard_guarded": clip,
                });
                println!("{}", serde_json::to_string_pretty(&out)?);
            } else if !clip {
                anyhow::bail!("either --output, --clip, or --json must be provided");
            }
            if clip {
                match std::str::from_utf8(&plain) {
                    Ok(text) => {
                        let _ = clipboard_guard::guard_interactive(
                            text,
                            clip_ttl,
                            Some("extracted secret"),
                        )?;
                    }
                    Err(_) => {
                        use base64::Engine;
                        let b64 = base64::engine::general_purpose::STANDARD.encode(&plain);
                        let _ = clipboard_guard::guard_interactive(
                            &b64,
                            clip_ttl,
                            Some("extracted binary (base64)"),
                        )?;
                    }
                }
            }
            plain.zeroize();
        }

        Commands::Capacity { carrier, json } => {
            let raw_bytes = fs::read(&carrier)
                .with_context(|| format!("failed to read carrier file: {}", carrier.display()))?;

            if raw_bytes.starts_with(b"BM") {
                let cap = bmp::get_bmp_capacity(&raw_bytes)?;
                if json {
                    let out = serde_json::json!({
                        "carrier": carrier.display().to_string(),
                        "carrier_type": "bmp",
                        "width": cap.width,
                        "height": cap.height,
                        "total_pixels": cap.total_pixels,
                        "channel_bytes": cap.channel_bytes,
                        "row_stride": cap.row_stride,
                        "row_padding": cap.row_padding,
                        "overhead_bytes": cap.overhead_bytes,
                        "total_capacity_bytes": cap.total_capacity_bytes,
                        "max_payload_bytes": cap.max_payload_bytes,
                        "max_payload_kib": (cap.max_payload_bytes as f64) / 1024.0,
                    });
                    println!("{}", serde_json::to_string_pretty(&out)?);
                } else {
                    println!("{}", "=== [CARRIER CAPACITY] ===".bold());
                    println!("  Target File:           {}", carrier.display());
                    println!("  Carrier Type:          BMP 24-bit Image Carrier");
                    println!(
                        "  Dimensions:            {} x {} ({} pixels)",
                        cap.width, cap.height, cap.total_pixels
                    );
                    println!(
                        "  Row Stride:            {} bytes (padding: {} bytes/row)",
                        cap.row_stride, cap.row_padding
                    );
                    println!(
                        "  Raw Channel Bytes:     {} bytes ({} bits)",
                        cap.channel_bytes, cap.channel_bytes
                    );
                    println!(
                        "  Envelope Overhead:     {} bytes (svLt magic + len + crc32)",
                        cap.overhead_bytes
                    );
                    println!(
                        "  Total Capacity:        {} bytes ({:.2} KiB)",
                        cap.total_capacity_bytes,
                        cap.total_capacity_bytes as f64 / 1024.0
                    );
                    println!(
                        "  Max Usable Payload:    {} bytes ({:.2} KiB)",
                        cap.max_payload_bytes,
                        cap.max_payload_bytes as f64 / 1024.0
                    );
                }
            } else if raw_bytes.len() >= 12
                && &raw_bytes[0..4] == b"RIFF"
                && &raw_bytes[8..12] == b"WAVE"
            {
                let cap = wav::get_wav_capacity(&raw_bytes)?;
                if json {
                    let out = serde_json::json!({
                        "carrier": carrier.display().to_string(),
                        "carrier_type": "wav",
                        "audio_format": cap.audio_format,
                        "num_channels": cap.num_channels,
                        "sample_rate": cap.sample_rate,
                        "bits_per_sample": cap.bits_per_sample,
                        "num_samples": cap.num_samples,
                        "lsb_overhead_bytes": cap.lsb_overhead_bytes,
                        "lsb_total_capacity_bytes": cap.lsb_total_capacity_bytes,
                        "lsb_max_payload_bytes": cap.lsb_max_payload_bytes,
                        "lsb_max_payload_kib": (cap.lsb_max_payload_bytes as f64) / 1024.0,
                        "chunk_mode_supported": cap.chunk_mode_supported,
                    });
                    println!("{}", serde_json::to_string_pretty(&out)?);
                } else {
                    println!("{}", "=== [CARRIER CAPACITY] ===".bold());
                    println!("  Target File:           {}", carrier.display());
                    println!("  Carrier Type:          WAV Audio Carrier");
                    println!(
                        "  Audio Format:          {} (channels: {}, {} Hz, {} bps)",
                        if cap.audio_format == 1 {
                            "PCM"
                        } else {
                            "non-PCM"
                        },
                        cap.num_channels,
                        cap.sample_rate,
                        cap.bits_per_sample
                    );
                    println!("  Total Audio Samples:   {}", cap.num_samples);
                    println!(
                        "  Mode: LSB Capacity:    {} bytes usable payload ({:.2} KiB)",
                        cap.lsb_max_payload_bytes,
                        cap.lsb_max_payload_bytes as f64 / 1024.0
                    );
                    println!(
                        "  Mode: Chunk Capacity:  Lossless RIFF metadata subchunk ('svLt', up to 4 GiB)"
                    );
                }
            } else if raw_bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
                if json {
                    let out = serde_json::json!({
                        "carrier": carrier.display().to_string(),
                        "carrier_type": "png",
                        "mode": "chunk",
                        "chunk_name": "svLt",
                        "max_chunk_payload_bytes": 0x7fff_ffffusize,
                    });
                    println!("{}", serde_json::to_string_pretty(&out)?);
                } else {
                    println!("{}", "=== [CARRIER CAPACITY] ===".bold());
                    println!("  Target File:           {}", carrier.display());
                    println!("  Carrier Type:          PNG Image Carrier");
                    println!(
                        "  Mode: Chunk Capacity:  Lossless private chunk ('svLt', up to 2 GiB)"
                    );
                    println!("  Max Chunk Size:        2,147,483,647 bytes");
                }
            } else {
                anyhow::bail!(
                    "unsupported carrier format for capacity estimation: {}",
                    carrier.display()
                );
            }
        }

        Commands::Inspect { input, json } => {
            if let Ok(mut f) = fs::File::open(&input) {
                let mut magic = [0u8; 4];
                if f.read_exact(&mut magic).is_ok() && &magic == stream::MAGIC {
                    let info = stream::inspect_stream_file(&input)?;
                    if json {
                        let mut out = serde_json::json!({
                            "target_file": input.display().to_string(),
                            "carrier_type": "stream",
                            "container_type": "stream",
                            "container_version": info.version,
                            "dpapi_bound": info.dpapi_bound,
                            "chunk_size": info.chunk_size,
                            "salt_hex": info.salt_hex,
                            "base_nonce_hex": info.base_nonce_hex,
                            "wrapped_key_bytes": info.wrapped_key_bytes,
                        });
                        if let Some(ref pol) = info.policy {
                            let now = policy::current_utc_timestamp();
                            out["policy"] = serde_json::json!({
                                "status": pol.status_at(now),
                                "status_summary": pol.status_summary(now),
                                "created_at": pol.created_at,
                                "created_at_iso": pol.format_created_at(),
                                "not_before": pol.not_before,
                                "not_before_iso": pol.format_not_before(),
                                "expires_at": pol.expires_at,
                                "expires_at_iso": pol.format_expires_at(),
                                "description": pol.description,
                            });
                        }
                        println!("{}", serde_json::to_string_pretty(&out)?);
                    } else {
                        println!("container_type:    stream (chunked AEAD)");
                        println!("container_version: {}", info.version);
                        println!("dpapi_bound:       {}", info.dpapi_bound);
                        println!(
                            "chunk_size:        {} bytes ({:.2} MiB)",
                            info.chunk_size,
                            info.chunk_size as f64 / (1024.0 * 1024.0)
                        );
                        println!("salt_hex:          {}", info.salt_hex);
                        println!("base_nonce_hex:    {}", info.base_nonce_hex);
                        if let Some(ref pol) = info.policy {
                            let now = policy::current_utc_timestamp();
                            println!("policy_header:     present");
                            println!("policy_status:     {}", pol.status_summary(now));
                            println!(
                                "policy_created_at: {} ({})",
                                pol.created_at,
                                pol.format_created_at()
                            );
                            if let Some(nb) = pol.not_before {
                                println!(
                                    "policy_not_before: {} ({})",
                                    nb,
                                    policy::format_iso8601_utc(nb)
                                );
                            }
                            if let Some(exp) = pol.expires_at {
                                println!(
                                    "policy_expires_at: {} ({})",
                                    exp,
                                    policy::format_iso8601_utc(exp)
                                );
                            }
                            if let Some(ref desc) = pol.description {
                                println!("policy_desc:       {}", desc);
                            }
                        }
                    }
                    return Ok(());
                }
            }

            let raw = fs::read(&input)
                .with_context(|| format!("failed to read file: {}", input.display()))?;
            let (carrier_type, container, armor_meta) = if armor::is_armored(&raw) {
                let text = std::str::from_utf8(&raw).context("armored file is not valid UTF-8")?;
                let meta = armor::inspect_armor(text)?;
                let dearmored = armor::dearmor_data(text)?;
                ("armor", dearmored.to_vec(), Some(meta))
            } else if raw.starts_with(b"\x89PNG\r\n\x1a\n") {
                ("png", stego::extract_from_png(&raw)?, None)
            } else if raw.len() >= 12 && &raw[0..4] == b"RIFF" && &raw[8..12] == b"WAVE" {
                (
                    "wav",
                    wav::extract_from_wav(&raw, wav::ExtractWavMode::Auto)?,
                    None,
                )
            } else if raw.starts_with(b"BM") {
                ("bmp", bmp::extract_from_bmp(&raw)?, None)
            } else {
                ("vault", raw, None)
            };

            if json {
                let info = if container.starts_with(b"SVLT") || armor_meta.is_none() {
                    Some(crypto::inspect(&container)?)
                } else {
                    None
                };
                let mut out = serde_json::json!({
                    "target_file": input.display().to_string(),
                    "carrier_type": carrier_type,
                });
                if let Some(ref meta) = armor_meta {
                    let intact = meta.stripes.iter().filter(|s| s.valid).count();
                    out["armored"] = serde_json::json!({
                        "version": meta.version,
                        "mode": meta.mode,
                        "data_stripes": meta.data_stripes,
                        "parity_stripes": meta.parity_stripes,
                        "original_length": meta.original_length,
                        "stripe_size": meta.stripe_size,
                        "payload_hash": meta.payload_hash,
                        "intact_stripes": intact,
                        "total_stripes": meta.stripes.len(),
                    });
                }
                if let Some(ref inf) = info {
                    out["container_version"] = serde_json::json!(inf.version);
                    out["dpapi_bound"] = serde_json::json!(inf.dpapi_bound);
                    out["payload_bytes"] = serde_json::json!(inf.payload_size);
                    out["salt_hex"] = serde_json::json!(inf.salt_hex);
                    out["decoy_container"] = serde_json::json!(inf.decoy_container);
                    if let Some(ref pol) = inf.policy {
                        let now = policy::current_utc_timestamp();
                        out["policy"] = serde_json::json!({
                            "status": pol.status_at(now),
                            "status_summary": pol.status_summary(now),
                            "created_at": pol.created_at,
                            "created_at_iso": pol.format_created_at(),
                            "not_before": pol.not_before,
                            "not_before_iso": pol.format_not_before(),
                            "expires_at": pol.expires_at,
                            "expires_at_iso": pol.format_expires_at(),
                            "description": pol.description,
                        });
                    }
                }
                println!("{}", serde_json::to_string_pretty(&out)?);
            } else {
                if let Some(ref meta) = armor_meta {
                    println!("armored_container: true");
                    println!("armor_version:     {}", meta.version);
                    println!("armor_mode:        {}", meta.mode);
                    println!("data_stripes:      {}", meta.data_stripes);
                    println!("parity_stripes:    {}", meta.parity_stripes);
                    println!("original_length:   {}", meta.original_length);
                    println!("stripe_size:       {}", meta.stripe_size);
                    println!("payload_hash:      {}", meta.payload_hash);
                    let intact = meta.stripes.iter().filter(|s| s.valid).count();
                    println!("intact_stripes:    {}/{}", intact, meta.stripes.len());
                }

                if container.starts_with(b"SVLT") || armor_meta.is_none() {
                    let info = crypto::inspect(&container)?;
                    println!("container_version: {}", info.version);
                    println!("dpapi_bound:       {}", info.dpapi_bound);
                    println!("payload_bytes:     {}", info.payload_size);
                    println!("salt_hex:          {}", info.salt_hex);
                    if info.decoy_container {
                        println!("decoy_container:   true");
                        println!("container_type:    decoy (plausible deniability)");
                    }
                    if let Some(ref pol) = info.policy {
                        let now = policy::current_utc_timestamp();
                        println!("policy_header:     present");
                        println!("policy_status:     {}", pol.status_summary(now));
                        println!(
                            "policy_created_at: {} ({})",
                            pol.created_at,
                            pol.format_created_at()
                        );
                        if let Some(nb) = pol.not_before {
                            println!(
                                "policy_not_before: {} ({})",
                                nb,
                                policy::format_iso8601_utc(nb)
                            );
                        }
                        if let Some(exp) = pol.expires_at {
                            println!(
                                "policy_expires_at: {} ({})",
                                exp,
                                policy::format_iso8601_utc(exp)
                            );
                        }
                        if let Some(ref desc) = pol.description {
                            println!("policy_desc:       {}", desc);
                        }
                    }
                }
            }
        }
        Commands::Shred {
            input,
            passes,
            json,
        } => {
            let wiped = shred::shred_file(&input, passes)?;
            if json {
                let out = serde_json::json!({
                    "status": "ok",
                    "command": "shred",
                    "target": input.display().to_string(),
                    "passes": passes,
                    "shredded_bytes": wiped,
                });
                println!("{}", serde_json::to_string_pretty(&out)?);
            } else {
                println!(
                    "{} shredded {} ({} bytes, {} passes)",
                    "ok".green().bold(),
                    input.display(),
                    wiped,
                    passes
                );
            }
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
        Commands::Armor {
            input,
            output,
            data_stripes,
            parity_stripes,
            clip,
            clip_ttl,
            json,
        } => {
            let raw = fs::read(&input)
                .with_context(|| format!("failed to read input file: {}", input.display()))?;
            let armored = armor::armor_data(&raw, data_stripes, parity_stripes)?;

            if let Some(ref out_path) = output {
                fs::write(out_path, &armored).with_context(|| {
                    format!("failed to write armored file: {}", out_path.display())
                })?;
            }

            if json {
                let out = serde_json::json!({
                    "status": "ok",
                    "command": "armor",
                    "input": input.display().to_string(),
                    "output": output.as_ref().map(|p| p.display().to_string()),
                    "original_bytes": raw.len(),
                    "armored_bytes": armored.len(),
                    "data_stripes": data_stripes,
                    "parity_stripes": parity_stripes,
                });
                println!("{}", serde_json::to_string_pretty(&out)?);
            } else if let Some(ref out_path) = output {
                println!(
                    "{} armored {} bytes -> {} (stripes: {}+{})",
                    "ok".green().bold(),
                    raw.len(),
                    out_path.display(),
                    data_stripes,
                    parity_stripes
                );
            } else if !clip {
                print!("{armored}");
            }

            if clip {
                let _ = clipboard_guard::guard_interactive(
                    &armored,
                    clip_ttl,
                    Some("armored container (.svault.asc)"),
                )?;
            }
        }
        Commands::Dearmor {
            input,
            output,
            clip,
            clip_ttl,
            json,
        } => {
            let raw_text = fs::read_to_string(&input)
                .with_context(|| format!("failed to read armored file: {}", input.display()))?;
            let mut plain = armor::dearmor_data(&raw_text)?;

            if let Some(ref out_path) = output {
                fs::write(out_path, &*plain).with_context(|| {
                    format!("failed to write dearmored file: {}", out_path.display())
                })?;
                if json {
                    let out = serde_json::json!({
                        "status": "ok",
                        "command": "dearmor",
                        "input": input.display().to_string(),
                        "output": out_path.display().to_string(),
                        "recovered_bytes": plain.len(),
                    });
                    println!("{}", serde_json::to_string_pretty(&out)?);
                } else {
                    println!(
                        "{} dearmored {} bytes -> {}",
                        "ok".green().bold(),
                        plain.len(),
                        out_path.display()
                    );
                }
            } else if json {
                let out = serde_json::json!({
                    "status": "ok",
                    "command": "dearmor",
                    "input": input.display().to_string(),
                    "output": serde_json::Value::Null,
                    "recovered_bytes": plain.len(),
                });
                println!("{}", serde_json::to_string_pretty(&out)?);
            } else if !clip {
                anyhow::bail!("either --output or --clip must be provided");
            }

            if clip {
                match std::str::from_utf8(&plain) {
                    Ok(text) => {
                        let _ = clipboard_guard::guard_interactive(
                            text,
                            clip_ttl,
                            Some("dearmored content"),
                        )?;
                    }
                    Err(_) => {
                        use base64::Engine;
                        let b64 = base64::engine::general_purpose::STANDARD.encode(&*plain);
                        let _ = clipboard_guard::guard_interactive(
                            &b64,
                            clip_ttl,
                            Some("dearmored binary (base64)"),
                        )?;
                    }
                }
            }
            plain.zeroize();
        }
        Commands::Repair {
            input,
            output,
            binary,
            json,
            clip,
            clip_ttl,
        } => {
            let raw_text = fs::read_to_string(&input)
                .with_context(|| format!("failed to read armored file: {}", input.display()))?;
            let (repaired_armored, mut recovered_bytes, report) = armor::repair_armored(&raw_text)?;

            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!(
                    "{} repair completed: {} intact, {} reconstructed out of {} stripes",
                    if report.success {
                        "ok".green().bold()
                    } else {
                        "warning".yellow().bold()
                    },
                    report.intact_stripes,
                    report.reconstructed_stripes,
                    report.total_stripes
                );
            }

            if let Some(ref out_path) = output {
                if binary {
                    fs::write(out_path, &*recovered_bytes).with_context(|| {
                        format!("failed to write repaired binary: {}", out_path.display())
                    })?;
                } else {
                    fs::write(out_path, &repaired_armored).with_context(|| {
                        format!(
                            "failed to write repaired armored file: {}",
                            out_path.display()
                        )
                    })?;
                }
            }

            if clip {
                if binary {
                    match std::str::from_utf8(&recovered_bytes) {
                        Ok(text) => {
                            let _ = clipboard_guard::guard_interactive(
                                text,
                                clip_ttl,
                                Some("repaired content"),
                            )?;
                        }
                        Err(_) => {
                            use base64::Engine;
                            let b64 =
                                base64::engine::general_purpose::STANDARD.encode(&*recovered_bytes);
                            let _ = clipboard_guard::guard_interactive(
                                &b64,
                                clip_ttl,
                                Some("repaired binary (base64)"),
                            )?;
                        }
                    }
                } else {
                    let _ = clipboard_guard::guard_interactive(
                        &repaired_armored,
                        clip_ttl,
                        Some("repaired armored container"),
                    )?;
                }
            }

            recovered_bytes.zeroize();
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
                    || raw_bytes.starts_with(b"BM")
                    || raw_bytes.starts_with(b"SVLT")
                    || armor::is_armored(&raw_bytes);

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
        Commands::Clip { action } => {
            handle_clip_command(action)?;
        }
        Commands::PackDir {
            input,
            output,
            mut passphrase,
            keyfile,
            dpapi,
            armor,
            carrier,
            list,
            not_before,
            expires_at,
            expires_in,
            policy_desc,
            json,
        } => {
            handle_pack_dir_command(
                &input,
                &output,
                passphrase.as_deref(),
                keyfile.as_deref(),
                dpapi,
                armor,
                carrier.as_deref(),
                list,
                not_before.as_deref(),
                expires_at.as_deref(),
                expires_in.as_deref(),
                policy_desc.as_deref(),
                json,
            )?;
            if let Some(ref mut p) = passphrase {
                p.zeroize();
            }
        }
        Commands::UnpackDir {
            input,
            output,
            mut passphrase,
            keyfile,
            list,
            verify_only,
            overwrite,
            at_time,
            json,
        } => {
            handle_unpack_dir_command(
                &input,
                output.as_deref(),
                passphrase.as_deref(),
                keyfile.as_deref(),
                list,
                verify_only,
                overwrite,
                at_time.as_deref(),
                json,
            )?;
            if let Some(ref mut p) = passphrase {
                p.zeroize();
            }
        }
        Commands::Keyfile { action } => {
            handle_keyfile_command(action)?;
        }
        Commands::Stream { action } => {
            handle_stream_command(action)?;
        }
        Commands::Compare {
            original,
            stego,
            json,
            detailed,
        } => {
            diff::handle_compare_command(&original, &stego, json, detailed)?;
        }
        Commands::Guard { action } => {
            handle_guard_command(action)?;
        }
        Commands::Keygen {
            words,
            separator,
            capitalize,
            number,
            length,
            no_symbols,
            no_numbers,
            no_upper,
            exclude_ambiguous,
            bytes,
            base64,
            base32,
            pin,
            seed,
            context,
            count,
            json,
            entropy,
            clip,
            clip_ttl,
        } => {
            let mode = if let Some(w) = words {
                passgen::PassgenMode::Diceware(passgen::DicewareOptions {
                    words: w,
                    separator,
                    capitalize,
                    number,
                })
            } else if let Some(b) = bytes {
                let encoding = if base64 {
                    passgen::ByteEncoding::Base64
                } else if base32 {
                    passgen::ByteEncoding::Base32
                } else {
                    passgen::ByteEncoding::Hex
                };
                passgen::PassgenMode::Bytes(b, encoding)
            } else if let Some(p) = pin {
                passgen::PassgenMode::Pin(p)
            } else {
                let char_len = length.unwrap_or(20);
                passgen::PassgenMode::Characters(passgen::CharOptions {
                    length: char_len,
                    no_symbols,
                    no_numbers,
                    no_upper,
                    no_lower: false,
                    exclude_ambiguous,
                })
            };

            let items = passgen::generate_batch(&mode, count, seed.as_deref(), context.as_deref())?;

            passgen::print_batch_cli(&items, json, entropy, clip, clip_ttl)?;
        }
        Commands::Rotate {
            input,
            output,
            in_place,
            mut old_passphrase,
            mut new_passphrase,
            old_keyfile,
            new_keyfile,
            dpapi,
            no_dpapi,
            clear_policy,
            json,
        } => {
            let out_target = if in_place {
                &input
            } else if let Some(ref o) = output {
                o
            } else {
                anyhow::bail!("either --output or --in-place must be specified");
            };

            if old_passphrase.is_none() && old_keyfile.is_none() {
                anyhow::bail!("either --old-passphrase or --old-keyfile must be provided");
            }
            if new_passphrase.is_none() && new_keyfile.is_none() {
                anyhow::bail!("either --new-passphrase or --new-keyfile must be provided");
            }

            let opts = rotate::RotateOptions {
                old_passphrase: old_passphrase.as_deref(),
                new_passphrase: new_passphrase.as_deref(),
                old_keyfile: old_keyfile.as_deref(),
                new_keyfile: new_keyfile.as_deref(),
                dpapi,
                no_dpapi,
                clear_policy,
            };

            check_guard_preflight(&input, None)?;
            let rotate_res = rotate::rotate_carrier_file(&input, out_target, &opts);
            if let Some(ref mut p) = old_passphrase {
                p.zeroize();
            }
            if let Some(ref mut p) = new_passphrase {
                p.zeroize();
            }
            let report = match rotate_res {
                Ok(rep) => {
                    let _ = guard::record_success(&input, None);
                    rep
                }
                Err(e) => {
                    handle_guard_post_failure(&input, None)?;
                    return Err(e.into());
                }
            };

            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!(
                    "{} rotated {} ({}) -> {} [payload: {} bytes, dpapi: {} -> {}, policy_preserved: {}, policy_cleared: {}]",
                    "ok".green().bold(),
                    report.input_path,
                    report.carrier_type,
                    report.output_path,
                    report.payload_bytes,
                    report.old_dpapi_bound,
                    report.new_dpapi_bound,
                    report.policy_preserved,
                    report.policy_cleared,
                );
            }
        }
        Commands::Canary { action } => match action {
            CanaryAction::Init {
                dir,
                output,
                mut passphrase,
                keyfile,
                all,
                json,
            } => {
                let report = canary::init_canary(
                    &dir,
                    output.as_deref(),
                    passphrase.as_deref(),
                    keyfile.as_deref(),
                    all,
                );
                if let Some(ref mut p) = passphrase {
                    p.zeroize();
                }
                let rep = report?;
                if json {
                    println!("{}", serde_json::to_string_pretty(&rep)?);
                } else {
                    println!(
                        "{} initialized canary manifest: {} (canary_id: {}, tracked: {} files, auth: {})",
                        "ok".green().bold(),
                        rep.manifest_path,
                        rep.canary_id,
                        rep.total_tracked,
                        rep.auth_mode,
                    );
                    for f in &rep.files {
                        println!(
                            "  - {:<12} {:>8} bytes  {:64}  {}",
                            format!("[{}]", f.carrier).cyan(),
                            f.size_bytes,
                            f.sha256,
                            f.path,
                        );
                    }
                }
            }
            CanaryAction::Verify {
                dir,
                manifest,
                mut passphrase,
                keyfile,
                strict,
                json,
            } => {
                let verify_res = canary::verify_canary(
                    &dir,
                    manifest.as_deref(),
                    passphrase.as_deref(),
                    keyfile.as_deref(),
                    strict,
                );
                if let Some(ref mut p) = passphrase {
                    p.zeroize();
                }
                let rep = verify_res?;
                if json {
                    println!("{}", serde_json::to_string_pretty(&rep)?);
                } else {
                    println!(
                        "=== [CANARY VERIFICATION] ===\n  Manifest:    {}\n  Canary ID:   {}\n  Created:     {}\n  Auth Mode:   {}\n  Signature:   {}\n  Tracked:     {} files (intact: {}, modified: {}, missing: {}, untracked: {})",
                        rep.manifest_path,
                        rep.canary_id,
                        rep.created_at_iso,
                        rep.auth_mode,
                        if rep.signature_valid {
                            "VALID".green().bold()
                        } else {
                            "INVALID / TAMPERED".red().bold()
                        },
                        rep.total_tracked,
                        rep.intact_count,
                        rep.modified_count,
                        rep.missing_count,
                        rep.untracked_count,
                    );

                    for rec in &rep.records {
                        match rec.status {
                            canary::FileIntegrityStatus::Intact => {
                                println!(
                                    "  {} {:<40} [{}]",
                                    "ok".green().bold(),
                                    rec.path,
                                    rec.carrier.as_deref().unwrap_or("file"),
                                );
                            }
                            canary::FileIntegrityStatus::Modified => {
                                println!(
                                    "  {} {:<40} {}",
                                    "MODIFIED".red().bold(),
                                    rec.path,
                                    rec.message.as_deref().unwrap_or("digest mismatch"),
                                );
                            }
                            canary::FileIntegrityStatus::Missing => {
                                println!(
                                    "  {} {:<40} {}",
                                    "MISSING".red().bold(),
                                    rec.path,
                                    rec.message.as_deref().unwrap_or("file not found"),
                                );
                            }
                            canary::FileIntegrityStatus::Untracked => {
                                println!(
                                    "  {} {:<40} (untracked file in target directory)",
                                    "UNTRACKED".yellow().bold(),
                                    rec.path,
                                );
                            }
                        }
                    }

                    if rep.is_clean {
                        println!(
                            "{} All {} canary files intact. Zero tampering detected.",
                            "ok".green().bold(),
                            rep.intact_count,
                        );
                    } else {
                        println!(
                            "{} Integrity check FAILED: {} modified, {} missing.",
                            "error".red().bold(),
                            rep.modified_count,
                            rep.missing_count,
                        );
                    }
                }
                if !rep.is_clean {
                    anyhow::bail!(
                        "canary verification failed: integrity compromised (signature_valid={}, modified={}, missing={}, untracked={})",
                        rep.signature_valid,
                        rep.modified_count,
                        rep.missing_count,
                        rep.untracked_count,
                    );
                }
            }
        },
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
            json,
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

            if json {
                let out = serde_json::json!({
                    "status": "ok",
                    "command": "totp add",
                    "name": record_name,
                    "vault": vault.display().to_string(),
                    "algorithm": record_algo.to_string(),
                    "digits": record_digits,
                    "period": record_period,
                    "dpapi": bind_dpapi,
                });
                println!("{}", serde_json::to_string_pretty(&out)?);
            } else {
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
        }

        TotpAction::Code {
            name,
            time,
            vault,
            mut passphrase,
            json,
            clip,
            clip_ttl,
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

            if clip {
                let _ = clipboard_guard::guard_interactive(&code, clip_ttl, Some(&record.name))?;
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
            json,
        } => {
            let mut vault_inst = totp::TotpVault::load(&vault, &passphrase)?;
            let removed = vault_inst.remove_record(&name)?;
            let bind_dpapi = dpapi || vault_inst.dpapi_bound;
            vault_inst.save(&vault, &passphrase, bind_dpapi)?;
            passphrase.zeroize();

            if json {
                let out = serde_json::json!({
                    "status": "ok",
                    "command": "totp remove",
                    "name": removed.name,
                    "vault": vault.display().to_string(),
                });
                println!("{}", serde_json::to_string_pretty(&out)?);
            } else {
                println!(
                    "{} removed TOTP record '{}' from {}",
                    "ok".green().bold(),
                    removed.name,
                    vault.display()
                );
            }
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
            json,
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

            if json {
                let out = serde_json::json!({
                    "status": "ok",
                    "command": "totp import",
                    "imported_count": imported,
                    "vault": vault.display().to_string(),
                    "dpapi": bind_dpapi,
                });
                println!("{}", serde_json::to_string_pretty(&out)?);
            } else {
                println!(
                    "{} imported {} record(s) into {}",
                    "ok".green().bold(),
                    imported,
                    vault.display()
                );
            }
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

fn handle_clip_command(action: ClipAction) -> Result<()> {
    match action {
        ClipAction::Copy {
            text,
            ttl,
            quiet,
            json,
        } => {
            if json {
                let guarded = clipboard_guard::copy_to_clipboard(&text)?;
                if ttl > 0 {
                    std::thread::spawn(move || {
                        std::thread::sleep(std::time::Duration::from_secs(ttl));
                        let _ = guarded.scrub();
                    });
                }
                let out = serde_json::json!({
                    "status": "ok",
                    "command": "clip copy",
                    "bytes": text.len(),
                    "ttl": ttl,
                });
                println!("{}", serde_json::to_string_pretty(&out)?);
            } else if quiet {
                let guarded = clipboard_guard::copy_to_clipboard(&text)?;
                if ttl > 0 {
                    std::thread::spawn(move || {
                        std::thread::sleep(std::time::Duration::from_secs(ttl));
                        let _ = guarded.scrub();
                    });
                }
            } else {
                let _ = clipboard_guard::guard_interactive(&text, ttl, None)?;
            }
        }
        ClipAction::Paste { json } => {
            let content = clipboard_guard::get_clipboard_text()?;
            if json {
                let out = serde_json::json!({
                    "has_text": content.is_some(),
                    "text": content,
                });
                println!("{}", serde_json::to_string_pretty(&out)?);
            } else if let Some(ref s) = content {
                print!("{s}");
                if !s.ends_with('\n') {
                    println!();
                }
            }
        }
        ClipAction::Clear { json } => {
            clipboard_guard::clear_clipboard()?;
            if json {
                let out = serde_json::json!({
                    "status": "ok",
                    "command": "clip clear",
                });
                println!("{}", serde_json::to_string_pretty(&out)?);
            } else {
                println!("{} clipboard cleared", "ok".green().bold());
            }
        }
        ClipAction::Status { json } => {
            let content = clipboard_guard::get_clipboard_text()?;
            let has_text = content.is_some();
            let length = content.as_ref().map(|s| s.len()).unwrap_or(0);
            let char_count = content.as_ref().map(|s| s.chars().count()).unwrap_or(0);
            let sha256_hex = content.as_ref().map(|s| {
                use sha2::{Digest, Sha256};
                let mut h = Sha256::new();
                h.update(s.as_bytes());
                format!("{:x}", h.finalize())
            });

            if json {
                let out = serde_json::json!({
                    "has_text": has_text,
                    "bytes": length,
                    "characters": char_count,
                    "sha256": sha256_hex,
                });
                println!("{}", serde_json::to_string_pretty(&out)?);
            } else {
                println!("{} Windows Clipboard Status", "=== [CLIPBOARD] ===".bold());
                println!(
                    "  Has Unicode Text:      {}",
                    if has_text {
                        "yes".green()
                    } else {
                        "no".dimmed()
                    }
                );
                if let Some(ref hash) = sha256_hex {
                    println!(
                        "  Text Length:           {} chars ({} bytes)",
                        char_count, length
                    );
                    println!("  SHA-256 Fingerprint:   {}", hash.cyan());
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
        if rep.carrier_type == audit::CarrierType::BmpImage {
            println!("  Stego Pixel LSB:       present (active)");
        } else {
            println!("  Stego PCM LSB:         present (active)");
        }
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

#[allow(clippy::too_many_arguments)]
fn handle_pack_dir_command(
    input: &Path,
    output: &Path,
    passphrase: Option<&str>,
    keyfile: Option<&Path>,
    dpapi: bool,
    armor: bool,
    carrier: Option<&Path>,
    list: bool,
    not_before: Option<&str>,
    expires_at: Option<&str>,
    expires_in: Option<&str>,
    policy_desc: Option<&str>,
    json: bool,
) -> Result<()> {
    if passphrase.is_none() && keyfile.is_none() {
        anyhow::bail!("either --passphrase or --keyfile must be provided");
    }

    let archive_bytes = archive::pack_directory(input)?;
    let summary = archive::list_archive(&archive_bytes)?;
    let policy = parse_cli_policy(not_before, expires_at, expires_in, policy_desc)?;

    if list && !json {
        println!(
            "{} packing {} entries ({} files, {} dirs, {} bytes)",
            "->".cyan().bold(),
            summary.total_entries,
            summary.file_count,
            summary.dir_count,
            summary.total_bytes
        );
        for entry in &summary.entries {
            let type_str = if entry.is_dir { "DIR " } else { "FILE" };
            println!(
                "  {} {:>8} bytes  [{}]  {}  {}",
                type_str.dimmed(),
                entry.size,
                entry.permissions,
                &entry.sha256[..16],
                entry.path
            );
        }
    }

    let sealed = crypto::seal_with_policy_and_keyfile(
        &archive_bytes,
        passphrase,
        keyfile,
        dpapi,
        policy.as_ref(),
    )?;

    if let Some(carrier_path) = carrier {
        let carrier_bytes = fs::read(carrier_path)
            .with_context(|| format!("failed to read carrier file: {}", carrier_path.display()))?;
        let output_bytes = if carrier_bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
            stego::embed_in_png(&carrier_bytes, &sealed)?
        } else if carrier_bytes.len() >= 12
            && &carrier_bytes[0..4] == b"RIFF"
            && &carrier_bytes[8..12] == b"WAVE"
        {
            wav::embed_in_wav(&carrier_bytes, &sealed, wav::WavMode::Chunk)?
        } else if carrier_bytes.starts_with(b"BM") {
            bmp::embed_in_bmp(&carrier_bytes, &sealed)?
        } else {
            anyhow::bail!(
                "unsupported carrier format: {} (expected PNG, WAV, or BMP)",
                carrier_path.display()
            );
        };
        fs::write(output, &output_bytes)
            .with_context(|| format!("failed to write carrier output: {}", output.display()))?;
    } else if armor || output.extension().and_then(|e| e.to_str()) == Some("asc") {
        let armored_text = armor::armor_data(&sealed, 4, 2)?;
        fs::write(output, armored_text.as_bytes())
            .with_context(|| format!("failed to write armored output: {}", output.display()))?;
    } else {
        fs::write(output, &sealed)
            .with_context(|| format!("failed to write container: {}", output.display()))?;
    }

    if json {
        let report = archive::PackReport {
            status: "ok".into(),
            files_packed: summary.file_count,
            dirs_packed: summary.dir_count,
            total_bytes: summary.total_bytes,
            archive_size: archive_bytes.len(),
            entries: summary.entries,
        };
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!(
            "{} packed {} files ({} bytes) -> {} (dpapi={})",
            "ok".green().bold(),
            summary.file_count,
            summary.total_bytes,
            output.display(),
            dpapi
        );
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn handle_unpack_dir_command(
    input: &Path,
    output: Option<&Path>,
    passphrase: Option<&str>,
    keyfile: Option<&Path>,
    list: bool,
    verify_only: bool,
    overwrite: bool,
    at_time: Option<&str>,
    json: bool,
) -> Result<()> {
    if passphrase.is_none() && keyfile.is_none() {
        anyhow::bail!("either --passphrase or --keyfile must be provided");
    }

    let raw_bytes = fs::read(input)
        .with_context(|| format!("failed to read input file: {}", input.display()))?;

    // Stego / Armor transparent carrier decoding
    let container = if armor::is_armored(&raw_bytes) {
        let text =
            std::str::from_utf8(&raw_bytes).context("armored container is not valid UTF-8")?;
        armor::dearmor_data(text)?.to_vec()
    } else if raw_bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        stego::extract_from_png(&raw_bytes)?
    } else if raw_bytes.len() >= 12 && &raw_bytes[0..4] == b"RIFF" && &raw_bytes[8..12] == b"WAVE" {
        wav::extract_from_wav(&raw_bytes, wav::ExtractWavMode::Auto)?
    } else if raw_bytes.starts_with(b"BM") {
        bmp::extract_from_bmp(&raw_bytes)?
    } else {
        raw_bytes
    };

    let at_time_val = parse_cli_at_time(at_time)?;
    check_guard_preflight(input, at_time_val)?;
    let plain = match crypto::open_at_with_keyfile(&container, passphrase, keyfile, at_time_val) {
        Ok(data) => {
            let _ = guard::record_success(input, at_time_val);
            data
        }
        Err(e) => {
            handle_guard_post_failure(input, at_time_val)?;
            return Err(e.into());
        }
    };

    if list {
        let summary = archive::list_archive(&plain)?;
        if json {
            println!("{}", serde_json::to_string_pretty(&summary)?);
        } else {
            println!(
                "{} archive contains {} entries ({} files, {} dirs, {} bytes):",
                "ok".green().bold(),
                summary.total_entries,
                summary.file_count,
                summary.dir_count,
                summary.total_bytes
            );
            println!(
                "  {:<6} {:>10}  {:<8}  {:<16}  PATH",
                "TYPE", "SIZE", "PERM", "SHA256 (16)"
            );
            println!("  {}", "-".repeat(70).dimmed());
            for entry in &summary.entries {
                let type_str = if entry.is_dir { "DIR" } else { "FILE" };
                let sha_short = if entry.is_dir {
                    "-".to_string()
                } else {
                    entry.sha256.chars().take(16).collect()
                };
                println!(
                    "  {:<6} {:>10}  {:<8}  {:<16}  {}",
                    type_str, entry.size, entry.permissions, sha_short, entry.path
                );
            }
        }
        return Ok(());
    }

    if verify_only {
        let report = archive::verify_archive(&plain)?;
        if json {
            println!("{}", serde_json::to_string_pretty(&report)?);
        } else {
            println!(
                "{} verified {} files ({} bytes) — all cryptographic SHA-256 digests intact",
                "ok".green().bold(),
                report.files_verified,
                report.total_bytes
            );
        }
        return Ok(());
    }

    let dest = output.ok_or_else(|| {
        anyhow::anyhow!("--output destination directory is required for extraction (or use --list / --verify-only)")
    })?;

    let report = archive::unpack_archive(&plain, dest, overwrite)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!(
            "{} unpacked {} files ({} bytes) -> {}",
            "ok".green().bold(),
            report.files_extracted,
            report.total_bytes,
            dest.display()
        );
    }

    Ok(())
}

fn handle_keyfile_command(action: KeyfileAction) -> Result<()> {
    match action {
        KeyfileAction::Generate {
            output,
            bytes,
            json,
        } => {
            keyfile::generate_keyfile(&output, bytes)?;
            let fp = keyfile::keyfile_fingerprint(&output)?;
            if json {
                let out = serde_json::json!({
                    "status": "ok",
                    "command": "keyfile generate",
                    "path": output.display().to_string(),
                    "bytes": bytes,
                    "fingerprint": fp,
                });
                println!("{}", serde_json::to_string_pretty(&out)?);
            } else {
                println!(
                    "{} generated cryptographic keyfile -> {} ({} bytes, fingerprint: {})",
                    "ok".green().bold(),
                    output.display(),
                    bytes,
                    fp
                );
            }
        }
        KeyfileAction::Inspect { path, json } => {
            let info = keyfile::inspect_keyfile(&path)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&info)?);
            } else {
                println!("{}", info.display_summary());
            }
        }
        KeyfileAction::Fingerprint { path, json } => {
            let fp = keyfile::keyfile_fingerprint(&path)?;
            if json {
                let out = serde_json::json!({
                    "path": path.display().to_string(),
                    "fingerprint": fp,
                });
                println!("{}", serde_json::to_string_pretty(&out)?);
            } else {
                println!("{fp}");
            }
        }
    }
    Ok(())
}

fn handle_stream_command(action: StreamAction) -> Result<()> {
    match action {
        StreamAction::Encrypt {
            input,
            output,
            mut passphrase,
            keyfile,
            dpapi,
            chunk_size,
            not_before,
            expires_at,
            expires_in,
            policy_desc,
            json,
        } => {
            let policy = parse_cli_policy(
                not_before.as_deref(),
                expires_at.as_deref(),
                expires_in.as_deref(),
                policy_desc.as_deref(),
            )?;
            let parsed_chunk_size = match chunk_size {
                Some(ref cs) => Some(stream::parse_chunk_size(cs)?),
                None => None,
            };
            let summary = stream::encrypt_file_stream(
                &input,
                &output,
                passphrase.as_deref(),
                keyfile.as_deref(),
                dpapi,
                policy.as_ref(),
                parsed_chunk_size,
            )?;
            if let Some(ref mut p) = passphrase {
                p.zeroize();
            }
            if json {
                let out = serde_json::json!({
                    "input": input.display().to_string(),
                    "output": output.display().to_string(),
                    "total_chunks": summary.total_chunks,
                    "total_plaintext_bytes": summary.total_plaintext_bytes,
                    "total_ciphertext_bytes": summary.total_ciphertext_bytes,
                    "chunk_size": summary.chunk_size,
                    "dpapi_bound": summary.dpapi_bound,
                    "salt_hex": summary.salt_hex,
                });
                println!("{}", serde_json::to_string_pretty(&out)?);
            } else {
                let policy_msg = match policy {
                    Some(ref p) => format!(
                        " policy={}",
                        p.status_summary(policy::current_utc_timestamp())
                    ),
                    None => String::new(),
                };
                println!(
                    "{} encrypted {} bytes in {} chunks -> {} (chunk_size: {} bytes, dpapi={}{})",
                    "ok".green().bold(),
                    summary.total_plaintext_bytes,
                    summary.total_chunks,
                    output.display(),
                    summary.chunk_size,
                    dpapi,
                    policy_msg
                );
            }
        }
        StreamAction::Decrypt {
            input,
            output,
            mut passphrase,
            keyfile,
            at_time,
            json,
        } => {
            let at_time_val = parse_cli_at_time(at_time.as_deref())?;
            check_guard_preflight(&input, at_time_val)?;
            let res = stream::decrypt_file_stream(
                &input,
                &output,
                passphrase.as_deref(),
                keyfile.as_deref(),
                at_time_val,
            );
            if let Some(ref mut p) = passphrase {
                p.zeroize();
            }
            let summary = match res {
                Ok(s) => {
                    let _ = guard::record_success(&input, at_time_val);
                    s
                }
                Err(e) => {
                    handle_guard_post_failure(&input, at_time_val)?;
                    return Err(e.into());
                }
            };
            if json {
                let out = serde_json::json!({
                    "input": input.display().to_string(),
                    "output": output.display().to_string(),
                    "total_chunks": summary.total_chunks,
                    "total_plaintext_bytes": summary.total_plaintext_bytes,
                    "total_ciphertext_bytes": summary.total_ciphertext_bytes,
                    "chunk_size": summary.chunk_size,
                    "dpapi_bound": summary.dpapi_bound,
                    "salt_hex": summary.salt_hex,
                });
                println!("{}", serde_json::to_string_pretty(&out)?);
            } else {
                println!(
                    "{} decrypted {} bytes in {} chunks -> {}",
                    "ok".green().bold(),
                    summary.total_plaintext_bytes,
                    summary.total_chunks,
                    output.display()
                );
            }
        }
        StreamAction::Inspect { input, json } => {
            let info = stream::inspect_stream_file(&input)?;
            if json {
                let mut out = serde_json::json!({
                    "target_file": input.display().to_string(),
                    "container_type": "stream",
                    "container_version": info.version,
                    "dpapi_bound": info.dpapi_bound,
                    "chunk_size": info.chunk_size,
                    "salt_hex": info.salt_hex,
                    "base_nonce_hex": info.base_nonce_hex,
                    "wrapped_key_bytes": info.wrapped_key_bytes,
                });
                if let Some(ref pol) = info.policy {
                    let now = policy::current_utc_timestamp();
                    out["policy"] = serde_json::json!({
                        "status": pol.status_at(now),
                        "status_summary": pol.status_summary(now),
                        "created_at": pol.created_at,
                        "created_at_iso": pol.format_created_at(),
                        "not_before": pol.not_before,
                        "not_before_iso": pol.format_not_before(),
                        "expires_at": pol.expires_at,
                        "expires_at_iso": pol.format_expires_at(),
                        "description": pol.description,
                    });
                }
                println!("{}", serde_json::to_string_pretty(&out)?);
            } else {
                println!("container_type:    stream (chunked AEAD)");
                println!("container_version: {}", info.version);
                println!("dpapi_bound:       {}", info.dpapi_bound);
                println!(
                    "chunk_size:        {} bytes ({:.2} MiB)",
                    info.chunk_size,
                    info.chunk_size as f64 / (1024.0 * 1024.0)
                );
                println!("salt_hex:          {}", info.salt_hex);
                println!("base_nonce_hex:    {}", info.base_nonce_hex);
                if let Some(ref pol) = info.policy {
                    let now = policy::current_utc_timestamp();
                    println!("policy_header:     present");
                    println!("policy_status:     {}", pol.status_summary(now));
                    println!(
                        "policy_created_at: {} ({})",
                        pol.created_at,
                        pol.format_created_at()
                    );
                    if let Some(nb) = pol.not_before {
                        println!(
                            "policy_not_before: {} ({})",
                            nb,
                            policy::format_iso8601_utc(nb)
                        );
                    }
                    if let Some(exp) = pol.expires_at {
                        println!(
                            "policy_expires_at: {} ({})",
                            exp,
                            policy::format_iso8601_utc(exp)
                        );
                    }
                    if let Some(ref desc) = pol.description {
                        println!("policy_desc:       {}", desc);
                    }
                }
            }
        }
    }
    Ok(())
}

fn handle_guard_command(action: GuardAction) -> Result<()> {
    match action {
        GuardAction::Arm {
            target,
            max_attempts,
            dead_man,
            deadline,
            passes,
            companion,
            json,
        } => {
            let dead_man_seconds = match dead_man {
                Some(ref s) => Some(policy::parse_duration(s)?),
                None => None,
            };
            let now = policy::current_utc_timestamp();
            let dead_man_dl = match deadline {
                Some(ref s) => Some(policy::parse_timestamp_or_duration(s, now)?),
                None => None,
            };
            let policy = guard::arm_guard(
                &target,
                max_attempts,
                dead_man_seconds,
                dead_man_dl,
                passes,
                companion,
                Some(now),
            )?;
            if json {
                let out = serde_json::json!({
                    "status": "ok",
                    "command": "guard arm",
                    "target": target.display().to_string(),
                    "max_attempts": policy.max_attempts,
                    "shred_passes": policy.shred_passes,
                    "companion": policy.companion,
                    "dead_man_deadline": policy.dead_man_deadline,
                    "dead_man_deadline_iso": policy.dead_man_deadline.map(policy::format_iso8601_utc),
                });
                println!("{}", serde_json::to_string_pretty(&out)?);
            } else {
                println!(
                    "{} armed guard on {} (max_attempts={}, passes={}, companion={})",
                    "ok".green().bold(),
                    target.display(),
                    policy.max_attempts,
                    policy.shred_passes,
                    policy.companion
                );
                if let Some(dl) = policy.dead_man_deadline {
                    println!(
                        "  dead-man deadline:     {} ({})",
                        dl,
                        policy::format_iso8601_utc(dl)
                    );
                }
            }
        }
        GuardAction::Status {
            target,
            json,
            at_time,
        } => {
            let at_time_val = parse_cli_at_time(at_time.as_deref())?;
            match guard::inspect_guard(&target, at_time_val)? {
                Some(rep) => {
                    if json {
                        println!("{}", serde_json::to_string_pretty(&rep)?);
                    } else {
                        println!("{}", "=== [GUARD STATUS] ===".bold());
                        println!("  Target:                {}", rep.target);
                        println!(
                            "  Active:                {}",
                            if rep.active {
                                "yes".green()
                            } else {
                                "no".dimmed()
                            }
                        );
                        println!("  Max Attempts:          {}", rep.max_attempts);
                        println!(
                            "  Failed Attempts:       {} (remaining: {})",
                            if rep.failed_attempts > 0 {
                                rep.failed_attempts.to_string().yellow().bold()
                            } else {
                                rep.failed_attempts.to_string().normal()
                            },
                            rep.remaining_attempts
                        );
                        println!("  Shred Passes:          {}", rep.shred_passes);
                        println!(
                            "  Created:               {} ({})",
                            rep.created_at, rep.created_at_iso
                        );
                        if let Some(dl) = rep.dead_man_deadline {
                            let exp_str = if rep.dead_man_expired {
                                " [EXPIRED]".red().bold()
                            } else {
                                "".normal()
                            };
                            println!(
                                "  Dead-Man Deadline:     {} ({}){}",
                                dl,
                                rep.dead_man_deadline_iso.as_deref().unwrap_or(""),
                                exp_str
                            );
                            if let Some(rem) = rep.dead_man_remaining_seconds {
                                println!("  Dead-Man Remaining:    {}s", rem);
                            }
                        } else {
                            println!("  Dead-Man Switch:       none");
                        }
                        println!(
                            "  Ledger Type:           {}",
                            if rep.companion {
                                "companion file"
                            } else {
                                "stealth system ledger"
                            }
                        );
                        println!("  Ledger Path:           {}", rep.guard_file_path);
                    }
                }
                None => {
                    if json {
                        let out = serde_json::json!({
                            "target": target.display().to_string(),
                            "active": false,
                            "guard_present": false,
                        });
                        println!("{}", serde_json::to_string_pretty(&out)?);
                    } else {
                        println!(
                            "{} no active guard policy found for {}",
                            "info:".cyan().bold(),
                            target.display()
                        );
                    }
                }
            }
        }
        GuardAction::Reset { target, json } => {
            let policy = guard::reset_guard(&target, None)?;
            if json {
                let out = serde_json::json!({
                    "status": "ok",
                    "command": "guard reset",
                    "target": target.display().to_string(),
                    "failed_attempts": 0,
                    "dead_man_deadline": policy.dead_man_deadline,
                    "dead_man_deadline_iso": policy.dead_man_deadline.map(policy::format_iso8601_utc),
                });
                println!("{}", serde_json::to_string_pretty(&out)?);
            } else {
                println!(
                    "{} reset failed attempts counter for {} (failed_attempts=0)",
                    "ok".green().bold(),
                    target.display()
                );
                if let Some(dl) = policy.dead_man_deadline {
                    println!(
                        "  refreshed deadline:    {} ({})",
                        dl,
                        policy::format_iso8601_utc(dl)
                    );
                }
            }
        }
        GuardAction::Checkin {
            target,
            interval,
            json,
        } => {
            let interval_secs = match interval {
                Some(ref s) => Some(policy::parse_duration(s)?),
                None => None,
            };
            let policy = guard::checkin_guard(&target, interval_secs, None)?;
            if json {
                let out = serde_json::json!({
                    "status": "ok",
                    "command": "guard checkin",
                    "target": target.display().to_string(),
                    "dead_man_deadline": policy.dead_man_deadline,
                    "dead_man_deadline_iso": policy.dead_man_deadline.map(policy::format_iso8601_utc),
                });
                println!("{}", serde_json::to_string_pretty(&out)?);
            } else {
                println!(
                    "{} checked-in dead-man switch for {}",
                    "ok".green().bold(),
                    target.display()
                );
                if let Some(dl) = policy.dead_man_deadline {
                    println!(
                        "  new deadline:          {} ({})",
                        dl,
                        policy::format_iso8601_utc(dl)
                    );
                }
            }
        }
        GuardAction::Disarm { target, json } => {
            let removed = guard::disarm_guard(&target)?;
            if json {
                let out = serde_json::json!({
                    "status": if removed { "ok" } else { "warning" },
                    "command": "guard disarm",
                    "target": target.display().to_string(),
                    "disarmed": removed,
                });
                println!("{}", serde_json::to_string_pretty(&out)?);
            } else if removed {
                println!(
                    "{} disarmed and removed guard protection from {}",
                    "ok".green().bold(),
                    target.display()
                );
            } else {
                println!(
                    "{} no active guard found to disarm for {}",
                    "warning:".yellow().bold(),
                    target.display()
                );
            }
        }
        GuardAction::Trigger {
            target,
            passes,
            force,
            json,
        } => {
            if !force {
                anyhow::bail!(
                    "emergency trigger permanently shreds '{}' ({} passes). Specify --force to confirm.",
                    target.display(),
                    passes
                );
            }
            let shredded = guard::emergency_trigger(&target, passes)?;
            if json {
                let out = serde_json::json!({
                    "status": "ok",
                    "command": "guard trigger",
                    "target": target.display().to_string(),
                    "passes": passes,
                    "shredded_bytes": shredded,
                });
                println!("{}", serde_json::to_string_pretty(&out)?);
            } else {
                println!(
                    "{} emergency triggered: shredded {} bytes ({} passes) -> {}",
                    "ok".red().bold(),
                    shredded,
                    passes,
                    target.display()
                );
            }
        }
        GuardAction::List { json, at_time } => {
            let at_time_val = parse_cli_at_time(at_time.as_deref())?;
            let reports = guard::list_guards(at_time_val)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&reports)?);
            } else {
                println!("{}", "=== [ACTIVE GUARD LEDGERS] ===".bold());
                if reports.is_empty() {
                    println!("  (no active stealth guards registered)");
                } else {
                    println!(
                        "  {:<35} {:<10} {:<12} {:<25}",
                        "TARGET", "ATTEMPTS", "DEAD-MAN", "LEDGER"
                    );
                    println!("  {}", "-".repeat(85));
                    for r in &reports {
                        let att_str = format!("{}/{}", r.failed_attempts, r.max_attempts);
                        let dm_str = if let Some(_dl) = r.dead_man_deadline {
                            if r.dead_man_expired {
                                "EXPIRED".to_string()
                            } else {
                                format!("{}s", r.dead_man_remaining_seconds.unwrap_or(0))
                            }
                        } else {
                            "none".to_string()
                        };
                        println!(
                            "  {:<35} {:<10} {:<12} {:<25}",
                            r.target,
                            att_str,
                            dm_str,
                            if r.companion { "companion" } else { "stealth" }
                        );
                    }
                }
            }
        }
    }
    Ok(())
}
