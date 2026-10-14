// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

//! Interactive in-memory terminal vault shell (`svault repl`).
//!
//! Provides an interactive read-eval-print loop (REPL) that unlocks an encrypted key-value
//! secret container once into RAM, and lets operators query, add, update, remove, and export
//! secrets without leaving plaintext artifacts on disk.

pub mod command;
pub mod store;

#[allow(unused_imports)]
pub use command::{execute_command, parse_command, tokenize_line, ReplCommand, ReplResponse};
#[allow(unused_imports)]
pub use store::{KeyValueVault, SecretEntry};

use crate::error::{Error, Result};
use colored::Colorize;
use std::io::{self, BufRead, IsTerminal, Write};
use std::path::PathBuf;
use std::time::Instant;
use zeroize::Zeroize;

/// Configuration options for the interactive REPL session.
#[derive(Debug, Clone)]
pub struct ReplConfig {
    pub vault_path: PathBuf,
    pub passphrase: Option<String>,
    pub keyfile: Option<PathBuf>,
    pub dpapi: bool,
    pub readonly: bool,
    pub auto_save: bool,
    pub json: bool,
}

impl Drop for ReplConfig {
    fn drop(&mut self) {
        if let Some(ref mut p) = self.passphrase {
            p.zeroize();
        }
    }
}

/// Active in-memory REPL session.
pub struct ReplSession {
    pub config: ReplConfig,
    pub vault: KeyValueVault,
    pub start_time: Instant,
    pub commands_executed: usize,
}

impl ReplSession {
    /// Initialize a new REPL session by unlocking an existing vault or creating a new store.
    pub fn new(config: ReplConfig) -> Result<Self> {
        let vault = KeyValueVault::load_or_new(
            &config.vault_path,
            config.passphrase.as_deref(),
            config.keyfile.as_deref(),
        )?;

        let mut session = Self {
            config,
            vault,
            start_time: Instant::now(),
            commands_executed: 0,
        };

        if session.config.dpapi {
            session.vault.dpapi_bound = true;
        }

        Ok(session)
    }

    /// Execute a single command line and return the response.
    pub fn execute_line(&mut self, line: &str) -> Result<ReplResponse> {
        let tokens = tokenize_line(line);
        if tokens.is_empty() {
            return Ok(ReplResponse {
                status: "ok".into(),
                message: String::new(),
                command: String::new(),
                data: None,
                should_exit: false,
                raw_output: None,
            });
        }

        let cmd = parse_command(&tokens)?;
        self.commands_executed += 1;

        execute_command(
            cmd,
            &mut self.vault,
            &self.config.vault_path,
            self.config.passphrase.as_deref(),
            self.config.keyfile.as_deref(),
            self.config.readonly,
            self.start_time,
            self.commands_executed,
        )
    }

    /// Execute batch of commands separated by semicolon or newline.
    pub fn exec_batch(&mut self, batch_str: &str) -> Result<()> {
        let lines: Vec<&str> = batch_str
            .split([';', '\n'])
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .collect();

        for line in lines {
            let resp = self.execute_line(line)?;
            if self.config.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&resp).unwrap_or_default()
                );
            } else if let Some(ref raw) = resp.raw_output {
                println!("{raw}");
            } else if !resp.message.is_empty() {
                println!("{}", resp.message);
            }

            if resp.should_exit {
                break;
            }
        }

        if self.config.auto_save && self.vault.is_dirty() && !self.config.readonly {
            self.vault.save(
                &self.config.vault_path,
                self.config.passphrase.as_deref(),
                self.config.keyfile.as_deref(),
                self.vault.dpapi_bound,
            )?;
        }

        Ok(())
    }

    /// Run the interactive session loop.
    pub fn run_loop(&mut self) -> Result<()> {
        let is_term = io::stdin().is_terminal();

        if is_term && !self.config.json {
            println!(
                "{}",
                "=== [ShadowVault Interactive Shell (svault repl)] ===".bold()
            );
            println!(
                "  Vault:    {} ({} entries, DPAPI: {})",
                self.config.vault_path.display(),
                self.vault.len(),
                if self.vault.dpapi_bound {
                    "enabled"
                } else {
                    "disabled"
                }
            );
            println!(
                "  Mode:     {}",
                if self.config.readonly {
                    "read-only (no disk mutations)".yellow()
                } else {
                    "read-write".green()
                }
            );
            println!(
                "  Type '{}' for help, '{}' to quit.\n",
                "help".cyan(),
                "exit".cyan()
            );
        }

        let stdin = io::stdin();
        let mut reader = stdin.lock();
        let mut line_buf = String::new();

        loop {
            if is_term && !self.config.json {
                let prompt = if self.vault.is_dirty() {
                    "svault* > ".yellow().bold()
                } else {
                    "svault > ".cyan().bold()
                };
                print!("{prompt}");
                io::stdout().flush().map_err(Error::Io)?;
            }

            line_buf.clear();
            let bytes_read = reader.read_line(&mut line_buf).map_err(Error::Io)?;
            if bytes_read == 0 {
                // EOF reached
                break;
            }

            let trimmed = line_buf.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            match self.execute_line(trimmed) {
                Ok(resp) => {
                    if self.config.json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&resp).unwrap_or_default()
                        );
                    } else if let Some(ref raw) = resp.raw_output {
                        println!("{raw}");
                    } else if !resp.message.is_empty() {
                        println!("{}", resp.message);
                    }

                    if resp.should_exit {
                        break;
                    }
                }
                Err(e) => {
                    if self.config.json {
                        let err_json = serde_json::json!({
                            "status": "error",
                            "error": e.to_string(),
                        });
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&err_json).unwrap_or_default()
                        );
                    } else {
                        eprintln!("{} {e}", "error:".red().bold());
                    }
                }
            }
        }

        if self.config.auto_save && self.vault.is_dirty() && !self.config.readonly {
            self.vault.save(
                &self.config.vault_path,
                self.config.passphrase.as_deref(),
                self.config.keyfile.as_deref(),
                self.vault.dpapi_bound,
            )?;
            if is_term && !self.config.json {
                println!("{}", "auto-saved vault changes upon exit.".green());
            }
        }

        Ok(())
    }
}

/// CLI runner for `svault repl` command.
pub fn run_cli(config: ReplConfig, exec: Option<String>) -> Result<()> {
    let mut session = ReplSession::new(config)?;

    if let Some(commands) = exec {
        session.exec_batch(&commands)
    } else {
        session.run_loop()
    }
}
