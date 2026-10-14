// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

//! Command parser and execution handler for the interactive vault REPL shell.

use crate::clipboard_guard;
use crate::error::{Error, Result};
use crate::repl::store::KeyValueVault;
use colored::Colorize;
use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

/// Parsed interactive REPL shell command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplCommand {
    Help,
    List {
        filter: Option<String>,
    },
    Get {
        key: String,
        clip: bool,
        clip_ttl: u64,
        reveal: bool,
        raw: bool,
    },
    Set {
        key: String,
        value: String,
        tag: Option<String>,
    },
    Del {
        key: String,
    },
    Save,
    Status,
    Export {
        path: PathBuf,
        raw: bool,
    },
    Import {
        path: PathBuf,
    },
    Clear,
    Exit {
        force: bool,
    },
}

/// Tokenize an input command line respecting single and double quotes.
pub fn tokenize_line(line: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_single = false;
    let mut in_double = false;
    for c in line.chars() {
        match c {
            '\'' if !in_double => {
                in_single = !in_single;
            }
            '"' if !in_single => {
                in_double = !in_double;
            }
            ' ' | '\t' | '\r' | '\n' if !in_single && !in_double => {
                if !current.is_empty() {
                    tokens.push(current);
                    current = String::new();
                }
            }
            _ => {
                current.push(c);
            }
        }
    }

    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

/// Parse a token list into a `ReplCommand`.
pub fn parse_command(tokens: &[String]) -> Result<ReplCommand> {
    if tokens.is_empty() {
        return Ok(ReplCommand::Help);
    }

    let verb = tokens[0].to_lowercase();
    match verb.as_str() {
        "help" | "?" => Ok(ReplCommand::Help),
        "list" | "ls" => {
            let filter = tokens.get(1).cloned();
            Ok(ReplCommand::List { filter })
        }
        "get" | "read" | "show" => {
            if tokens.len() < 2 {
                return Err(Error::Repl(
                    "usage: get <key> [--clip] [--clip-ttl <sec>] [--reveal] [--raw]".into(),
                ));
            }
            let key = tokens[1].clone();
            let mut clip = false;
            let mut clip_ttl = 15;
            let mut reveal = false;
            let mut raw = false;

            let mut i = 2;
            while i < tokens.len() {
                match tokens[i].as_str() {
                    "--clip" | "-c" => clip = true,
                    "--clip-ttl" => {
                        i += 1;
                        if i < tokens.len() {
                            clip_ttl = tokens[i].parse::<u64>().unwrap_or(15);
                        }
                    }
                    "--reveal" | "-r" => reveal = true,
                    "--raw" => raw = true,
                    _ => {}
                }
                i += 1;
            }
            Ok(ReplCommand::Get {
                key,
                clip,
                clip_ttl,
                reveal,
                raw,
            })
        }
        "set" | "add" | "put" => {
            if tokens.len() < 3 {
                return Err(Error::Repl("usage: set <key> <value> [--tag <tag>]".into()));
            }
            let key = tokens[1].clone();
            let value = tokens[2].clone();
            let mut tag = None;

            let mut i = 3;
            while i < tokens.len() {
                if tokens[i] == "--tag" || tokens[i] == "-t" {
                    i += 1;
                    if i < tokens.len() {
                        tag = Some(tokens[i].clone());
                    }
                }
                i += 1;
            }
            Ok(ReplCommand::Set { key, value, tag })
        }
        "del" | "rm" | "delete" => {
            if tokens.len() < 2 {
                return Err(Error::Repl("usage: del <key>".into()));
            }
            Ok(ReplCommand::Del {
                key: tokens[1].clone(),
            })
        }
        "save" | "write" | "commit" => Ok(ReplCommand::Save),
        "status" | "info" => Ok(ReplCommand::Status),
        "export" => {
            if tokens.len() < 2 {
                return Err(Error::Repl("usage: export <path> [--raw]".into()));
            }
            let path = PathBuf::from(&tokens[1]);
            let raw = tokens.iter().any(|t| t == "--raw");
            Ok(ReplCommand::Export { path, raw })
        }
        "import" => {
            if tokens.len() < 2 {
                return Err(Error::Repl("usage: import <path>".into()));
            }
            let path = PathBuf::from(&tokens[1]);
            Ok(ReplCommand::Import { path })
        }
        "clear" | "cls" => Ok(ReplCommand::Clear),
        "exit" | "quit" | "q" => {
            let force = tokens
                .iter()
                .any(|t| t == "--force" || t == "-f" || t == "!");
            Ok(ReplCommand::Exit { force })
        }
        "exit!" => Ok(ReplCommand::Exit { force: true }),
        other => Err(Error::Repl(format!(
            "unknown shell command: '{other}'. Type 'help' for available commands."
        ))),
    }
}

/// Structured response from executing a REPL command.
#[derive(Debug, Clone, Serialize)]
pub struct ReplResponse {
    pub status: String,
    pub message: String,
    pub command: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
    #[serde(skip)]
    pub should_exit: bool,
    #[serde(skip)]
    pub raw_output: Option<String>,
}

/// Execute a REPL command against the active session and vault.
#[allow(clippy::too_many_arguments)]
pub fn execute_command(
    cmd: ReplCommand,
    vault: &mut KeyValueVault,
    vault_path: &Path,
    passphrase: Option<&str>,
    keyfile: Option<&Path>,
    readonly: bool,
    start_time: Instant,
    commands_executed: usize,
) -> Result<ReplResponse> {
    match cmd {
        ReplCommand::Help => {
            let help_text = format!(
                "{}\n\
                   {:<26} {}\n\
                   {:<26} {}\n\
                   {:<26} {}\n\
                   {:<26} {}\n\
                   {:<26} {}\n\
                   {:<26} {}\n\
                   {:<26} {}\n\
                   {:<26} {}\n\
                   {:<26} {}\n\
                   {:<26} {}",
                "Available Shell Commands:".bold(),
                "list [filter]".cyan(),
                "List secret keys, sizes, and timestamps",
                "get <key> [flags]".cyan(),
                "Retrieve secret (--clip, --reveal, --raw)",
                "set <key> <val> [--tag T]".cyan(),
                "Insert or update a secret value",
                "del <key>".cyan(),
                "Delete a secret key from memory",
                "save".cyan(),
                "Re-encrypt and atomically save vault to disk",
                "status".cyan(),
                "Display active session status and memory info",
                "export <path> [--raw]".cyan(),
                "Export secrets to JSON file",
                "import <path>".cyan(),
                "Import secrets from JSON file into session",
                "clear".cyan(),
                "Clear terminal display",
                "exit [--force]".cyan(),
                "Securely zeroize session and quit"
            );
            Ok(ReplResponse {
                status: "ok".into(),
                message: help_text,
                command: "help".into(),
                data: None,
                should_exit: false,
                raw_output: None,
            })
        }
        ReplCommand::List { filter } => {
            let entries = vault.list(filter.as_deref());
            let list_data: Vec<serde_json::Value> = entries
                .iter()
                .map(|e| {
                    serde_json::json!({
                        "key": e.key,
                        "tag": e.tag,
                        "bytes": e.value.len(),
                        "created_at": e.created_at,
                        "updated_at": e.updated_at,
                    })
                })
                .collect();

            let mut msg = format!(
                "{} entries in vault (filter: {:?}):",
                entries.len(),
                filter.unwrap_or_else(|| "*".into())
            );
            if !entries.is_empty() {
                msg.push_str(&format!(
                    "\n  {:<24} {:<12} {:>8}  {:<19}",
                    "KEY".bold(),
                    "TAG".bold(),
                    "SIZE".bold(),
                    "UPDATED".bold()
                ));
                msg.push_str(&format!("\n  {}", "-".repeat(68).dimmed()));
                for e in &entries {
                    let tag_str = e.tag.as_deref().unwrap_or("-");
                    msg.push_str(&format!(
                        "\n  {:<24} {:<12} {:>6} B  {}",
                        e.key.green(),
                        tag_str.dimmed(),
                        e.value.len(),
                        e.updated_at
                    ));
                }
            }

            Ok(ReplResponse {
                status: "ok".into(),
                message: msg,
                command: "list".into(),
                data: Some(serde_json::json!(list_data)),
                should_exit: false,
                raw_output: None,
            })
        }
        ReplCommand::Get {
            key,
            clip,
            clip_ttl,
            reveal,
            raw,
        } => {
            let entry = vault
                .get(&key)
                .ok_or_else(|| Error::Repl(format!("key '{key}' not found in vault")))?;

            if clip {
                let guarded = clipboard_guard::copy_to_clipboard(&entry.value)?;
                if clip_ttl > 0 {
                    std::thread::spawn(move || {
                        std::thread::sleep(std::time::Duration::from_secs(clip_ttl));
                        let _ = guarded.scrub();
                    });
                }
            }

            if raw {
                return Ok(ReplResponse {
                    status: "ok".into(),
                    message: entry.value.clone(),
                    command: "get".into(),
                    data: Some(serde_json::json!({
                        "key": entry.key,
                        "value": entry.value,
                        "tag": entry.tag,
                    })),
                    should_exit: false,
                    raw_output: Some(entry.value.clone()),
                });
            }

            let value_display = if reveal {
                entry.value.clone()
            } else {
                entry.masked_preview()
            };

            let clip_note = if clip {
                format!(" (copied to clipboard, auto-wipes in {}s)", clip_ttl)
            } else {
                String::new()
            };

            let msg = format!(
                "{}: {}{}",
                entry.key.bold(),
                value_display.yellow(),
                clip_note.cyan()
            );

            Ok(ReplResponse {
                status: "ok".into(),
                message: msg,
                command: "get".into(),
                data: Some(serde_json::json!({
                    "key": entry.key,
                    "value": entry.value,
                    "tag": entry.tag,
                    "created_at": entry.created_at,
                    "updated_at": entry.updated_at,
                    "clipped": clip,
                    "clip_ttl": if clip { Some(clip_ttl) } else { None },
                })),
                should_exit: false,
                raw_output: None,
            })
        }
        ReplCommand::Set { key, value, tag } => {
            if readonly {
                return Err(Error::Repl(
                    "session is read-only: cannot mutate secrets".into(),
                ));
            }
            let is_update = vault.set(key.clone(), value.clone(), tag.clone());
            let action = if is_update { "updated" } else { "created" };
            let msg = format!(
                "{} secret '{}' ({} bytes, tag: {:?})",
                action,
                key.green().bold(),
                value.len(),
                tag
            );

            Ok(ReplResponse {
                status: "ok".into(),
                message: msg,
                command: "set".into(),
                data: Some(serde_json::json!({
                    "key": key,
                    "updated": is_update,
                    "tag": tag,
                    "bytes": value.len(),
                })),
                should_exit: false,
                raw_output: None,
            })
        }
        ReplCommand::Del { key } => {
            if readonly {
                return Err(Error::Repl(
                    "session is read-only: cannot delete secrets".into(),
                ));
            }
            let removed = vault.remove(&key);
            match removed {
                Some(entry) => Ok(ReplResponse {
                    status: "ok".into(),
                    message: format!("removed secret '{}' from vault", entry.key.red()),
                    command: "del".into(),
                    data: Some(serde_json::json!({
                        "key": key,
                        "removed": true,
                    })),
                    should_exit: false,
                    raw_output: None,
                }),
                None => Err(Error::Repl(format!("key '{key}' not found in vault"))),
            }
        }
        ReplCommand::Save => {
            if readonly {
                return Err(Error::Repl(
                    "session is read-only: cannot save vault".into(),
                ));
            }
            vault.save(vault_path, passphrase, keyfile, vault.dpapi_bound)?;
            Ok(ReplResponse {
                status: "ok".into(),
                message: format!(
                    "re-encrypted and saved {} entries to {}",
                    vault.len(),
                    vault_path.display()
                ),
                command: "save".into(),
                data: Some(serde_json::json!({
                    "vault": vault_path.display().to_string(),
                    "entries": vault.len(),
                    "dpapi_bound": vault.dpapi_bound,
                })),
                should_exit: false,
                raw_output: None,
            })
        }
        ReplCommand::Status => {
            let uptime_secs = start_time.elapsed().as_secs();
            let msg = format!(
                "{}\n\
                   Vault File:       {}\n\
                   Entries:          {}\n\
                   Dirty (Modified): {}\n\
                   Read-Only:        {}\n\
                   DPAPI Bound:      {}\n\
                   Session Uptime:   {}s ({} commands)",
                "=== [VAULT REPL SESSION STATUS] ===".bold(),
                vault_path.display(),
                vault.len(),
                if vault.is_dirty() {
                    "yes (unsaved changes)".yellow().bold()
                } else {
                    "no (clean)".green()
                },
                if readonly {
                    "yes".yellow()
                } else {
                    "no".green()
                },
                if vault.dpapi_bound {
                    "enabled".cyan()
                } else {
                    "disabled".dimmed()
                },
                uptime_secs,
                commands_executed
            );

            Ok(ReplResponse {
                status: "ok".into(),
                message: msg,
                command: "status".into(),
                data: Some(serde_json::json!({
                    "vault": vault_path.display().to_string(),
                    "entries": vault.len(),
                    "dirty": vault.is_dirty(),
                    "readonly": readonly,
                    "dpapi_bound": vault.dpapi_bound,
                    "uptime_seconds": uptime_secs,
                    "commands_executed": commands_executed,
                })),
                should_exit: false,
                raw_output: None,
            })
        }
        ReplCommand::Export { path, raw } => {
            let json_str = vault.export_json(raw)?;
            fs::write(&path, json_str.as_bytes()).map_err(Error::Io)?;
            Ok(ReplResponse {
                status: "ok".into(),
                message: format!(
                    "exported {} entries to {} (raw: {})",
                    vault.len(),
                    path.display(),
                    raw
                ),
                command: "export".into(),
                data: Some(serde_json::json!({
                    "path": path.display().to_string(),
                    "entries": vault.len(),
                    "raw": raw,
                })),
                should_exit: false,
                raw_output: None,
            })
        }
        ReplCommand::Import { path } => {
            if readonly {
                return Err(Error::Repl(
                    "session is read-only: cannot import secrets".into(),
                ));
            }
            let text = fs::read_to_string(&path).map_err(Error::Io)?;
            let imported = vault.import_json(&text)?;
            Ok(ReplResponse {
                status: "ok".into(),
                message: format!("imported {} secret(s) from {}", imported, path.display()),
                command: "import".into(),
                data: Some(serde_json::json!({
                    "path": path.display().to_string(),
                    "imported_count": imported,
                    "total_entries": vault.len(),
                })),
                should_exit: false,
                raw_output: None,
            })
        }
        ReplCommand::Clear => {
            print!("\x1B[2J\x1B[1;1H");
            let _ = std::io::Write::flush(&mut std::io::stdout());
            Ok(ReplResponse {
                status: "ok".into(),
                message: String::new(),
                command: "clear".into(),
                data: None,
                should_exit: false,
                raw_output: None,
            })
        }
        ReplCommand::Exit { force } => {
            if vault.is_dirty() && !force && !readonly {
                return Err(Error::Repl(
                    "unsaved changes exist. Type 'save' then 'exit', or 'exit --force' / 'exit!' to discard."
                        .into(),
                ));
            }
            Ok(ReplResponse {
                status: "ok".into(),
                message: "session closed; sensitive buffers zeroized.".into(),
                command: "exit".into(),
                data: Some(serde_json::json!({
                    "closed": true,
                    "zeroized": true,
                })),
                should_exit: true,
                raw_output: None,
            })
        }
    }
}
