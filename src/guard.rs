// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

//! Dead-Man's Switch and Maximum Attempt Self-Destruction Guard Engine.
//!
//! Provides automated defense against unauthorized physical access and brute-force
//! attacks by maintaining an authenticated, tamper-resistant attempt ledger.
//!
//! When configured on a container or carrier, the guard automatically monitors
//! consecutive failed passphrase attempts. If the threshold $K$ is reached or if
//! a dead-man inactivity deadline lapses without check-in, the guard executes a
//! multi-pass cryptographic file shredding sequence via [`crate::shred::shred_file`].

use crate::error::{Error, Result};
use crate::policy::{current_utc_timestamp, format_iso8601_utc};
use crate::shred::shred_file;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

/// Default number of shredding overwrite passes on self-destruction.
pub const DEFAULT_SHRED_PASSES: u8 = 3;

/// Core guard configuration and operational state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GuardPolicy {
    pub target_path: String,
    pub target_fingerprint: String,
    pub max_attempts: u32,
    pub failed_attempts: u32,
    pub shred_passes: u8,
    pub created_at: u64,
    pub last_attempt_at: Option<u64>,
    pub last_success_at: Option<u64>,
    pub dead_man_deadline: Option<u64>,
    pub dead_man_interval_seconds: Option<u64>,
    pub companion: bool,
    pub active: bool,
    pub signature: String,
}

/// Action outcome returned after checking or updating the guard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuardAction {
    /// Attempt allowed; vault may proceed to decryption attempt.
    Allowed { remaining_attempts: Option<u32> },
    /// Authentication failed, but attempts remain below threshold.
    AttemptFailed {
        failed_attempts: u32,
        max_attempts: u32,
        remaining: u32,
    },
    /// Threshold exceeded or deadline expired; vault was permanently shredded.
    SelfShredTriggered {
        reason: ShredReason,
        passes: u8,
        target_path: PathBuf,
    },
}

/// Specific reason triggering self-destruction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ShredReason {
    MaxAttemptsExceeded { attempts: u32, limit: u32 },
    DeadManSwitchExpired { deadline: u64, current_time: u64 },
    ManualEmergencyTrigger,
    TamperedLedger,
}

/// Structured inspection summary for human and machine consumption.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardStatusReport {
    pub target: String,
    pub active: bool,
    pub max_attempts: u32,
    pub failed_attempts: u32,
    pub remaining_attempts: u32,
    pub shred_passes: u8,
    pub created_at: u64,
    pub created_at_iso: String,
    pub last_attempt_at: Option<u64>,
    pub last_attempt_iso: Option<String>,
    pub last_success_at: Option<u64>,
    pub last_success_iso: Option<String>,
    pub dead_man_deadline: Option<u64>,
    pub dead_man_deadline_iso: Option<String>,
    pub dead_man_remaining_seconds: Option<i64>,
    pub dead_man_expired: bool,
    pub companion: bool,
    pub guard_file_path: String,
}

/// Compute SHA-256 fingerprint of a target file.
pub fn compute_file_fingerprint(path: &Path) -> Result<String> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 16384];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

/// Compute normalized canonical path hash for stealth ledger addressing.
fn path_hash(path: &Path) -> String {
    let norm = path
        .canonicalize()
        .unwrap_or_else(|_| path.to_path_buf())
        .to_string_lossy()
        .to_string();
    format!("{:x}", Sha256::digest(norm.as_bytes()))
}

/// Return companion file path (`<target>.guard`).
pub fn companion_path(target: &Path) -> PathBuf {
    let mut os_str = target.as_os_str().to_os_string();
    os_str.push(".guard");
    PathBuf::from(os_str)
}

/// Directory for centralized stealth guard ledgers.
pub fn stealth_ledger_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("SVAULT_GUARD_DIR") {
        return PathBuf::from(dir);
    }
    let base = if let Ok(profile) = std::env::var("USERPROFILE") {
        PathBuf::from(profile)
    } else if let Ok(home) = std::env::var("HOME") {
        PathBuf::from(home)
    } else {
        std::env::temp_dir()
    };
    base.join(".shadow-vault").join("guards")
}

/// Compute cryptographic tamper signature over policy state.
fn compute_signature(policy: &GuardPolicy) -> String {
    let mut hasher = Sha256::new();
    let user_seed = std::env::var("USERNAME")
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_else(|_| "svault_system_guard".into());
    hasher.update(user_seed.as_bytes());
    hasher.update(b"|svault_guard_v1|");
    hasher.update(policy.target_path.as_bytes());
    hasher.update(policy.target_fingerprint.as_bytes());
    hasher.update(policy.max_attempts.to_le_bytes());
    hasher.update(policy.failed_attempts.to_le_bytes());
    hasher.update([policy.shred_passes]);
    hasher.update(policy.created_at.to_le_bytes());
    hasher.update(policy.dead_man_deadline.unwrap_or(0).to_le_bytes());
    hasher.update(policy.dead_man_interval_seconds.unwrap_or(0).to_le_bytes());
    hasher.update([if policy.active { 1 } else { 0 }]);
    format!("{:x}", hasher.finalize())
}

/// Save policy to path with fresh authenticity signature.
fn save_policy(path: &Path, policy: &mut GuardPolicy) -> Result<()> {
    policy.signature = compute_signature(policy);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(policy)
        .map_err(|e| Error::Format(format!("failed to serialize guard policy: {e}")))?;
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)?;
    file.write_all(json.as_bytes())?;
    file.sync_all()?;
    Ok(())
}

/// Locate active guard policy (companion file takes priority, then stealth ledger).
pub fn find_guard(target: &Path) -> Result<Option<(PathBuf, GuardPolicy)>> {
    let comp = companion_path(target);
    if comp.exists() {
        return load_policy(&comp).map(|p| Some((comp, p)));
    }
    let stealth = stealth_ledger_dir().join(format!("{}.guard", path_hash(target)));
    if stealth.exists() {
        return load_policy(&stealth).map(|p| Some((stealth, p)));
    }
    Ok(None)
}

/// Load and authenticate a policy file from disk.
fn load_policy(path: &Path) -> Result<GuardPolicy> {
    let data = fs::read_to_string(path)?;
    let policy: GuardPolicy = serde_json::from_str(&data)
        .map_err(|e| Error::Format(format!("corrupted guard ledger format: {e}")))?;
    let expected_sig = compute_signature(&policy);
    if policy.signature != expected_sig {
        return Err(Error::Format(
            "guard ledger integrity violation: signature mismatch (tampering detected)".into(),
        ));
    }
    Ok(policy)
}

/// Arm a target file with a new max-attempt guard or dead-man switch.
pub fn arm_guard(
    target: &Path,
    max_attempts: u32,
    dead_man_seconds: Option<u64>,
    dead_man_deadline: Option<u64>,
    shred_passes: u8,
    companion: bool,
    now: Option<u64>,
) -> Result<GuardPolicy> {
    if !target.exists() {
        return Err(Error::Format(format!(
            "target file does not exist: {}",
            target.display()
        )));
    }
    if max_attempts == 0 {
        return Err(Error::Format("maximum attempts must be at least 1".into()));
    }

    let timestamp = now.unwrap_or_else(current_utc_timestamp);
    let fp = compute_file_fingerprint(target)?;
    let deadline = if let Some(dl) = dead_man_deadline {
        Some(dl)
    } else {
        dead_man_seconds.map(|s| timestamp.saturating_add(s))
    };

    let norm_path = target
        .canonicalize()
        .unwrap_or_else(|_| target.to_path_buf())
        .to_string_lossy()
        .to_string();

    let mut policy = GuardPolicy {
        target_path: norm_path,
        target_fingerprint: fp,
        max_attempts,
        failed_attempts: 0,
        shred_passes: shred_passes.max(1),
        created_at: timestamp,
        last_attempt_at: None,
        last_success_at: None,
        dead_man_deadline: deadline,
        dead_man_interval_seconds: dead_man_seconds,
        companion,
        active: true,
        signature: String::new(),
    };

    let path = if companion {
        companion_path(target)
    } else {
        stealth_ledger_dir().join(format!("{}.guard", path_hash(target)))
    };

    save_policy(&path, &mut policy)?;
    Ok(policy)
}

/// Pre-flight guard evaluation before passphrase verification.
pub fn check_guard_before_attempt(
    target: &Path,
    at_time: Option<u64>,
) -> Result<Option<GuardAction>> {
    let (policy_path, policy) = match find_guard(target)? {
        Some(pair) => pair,
        None => return Ok(None),
    };

    if !policy.active {
        return Ok(None);
    }

    let now = at_time.unwrap_or_else(current_utc_timestamp);

    // 1. Evaluate Dead-Man's Switch deadline
    if let Some(deadline) = policy.dead_man_deadline {
        if now >= deadline {
            let passes = policy.shred_passes;
            let target_buf = target.to_path_buf();
            let _ = shred_file(target, passes);
            let _ = fs::remove_file(&policy_path);
            return Ok(Some(GuardAction::SelfShredTriggered {
                reason: ShredReason::DeadManSwitchExpired {
                    deadline,
                    current_time: now,
                },
                passes,
                target_path: target_buf,
            }));
        }
    }

    // 2. Evaluate existing failed attempts counter
    if policy.failed_attempts >= policy.max_attempts {
        let passes = policy.shred_passes;
        let target_buf = target.to_path_buf();
        let _ = shred_file(target, passes);
        let _ = fs::remove_file(&policy_path);
        return Ok(Some(GuardAction::SelfShredTriggered {
            reason: ShredReason::MaxAttemptsExceeded {
                attempts: policy.failed_attempts,
                limit: policy.max_attempts,
            },
            passes,
            target_path: target_buf,
        }));
    }

    let remaining = policy.max_attempts.saturating_sub(policy.failed_attempts);
    Ok(Some(GuardAction::Allowed {
        remaining_attempts: Some(remaining),
    }))
}

/// Record a failed passphrase attempt and trigger shredding if limit reached.
pub fn record_failure(target: &Path, at_time: Option<u64>) -> Result<GuardAction> {
    let (policy_path, mut policy) = match find_guard(target)? {
        Some(pair) => pair,
        None => {
            return Ok(GuardAction::Allowed {
                remaining_attempts: None,
            })
        }
    };

    if !policy.active {
        return Ok(GuardAction::Allowed {
            remaining_attempts: None,
        });
    }

    let now = at_time.unwrap_or_else(current_utc_timestamp);
    policy.failed_attempts = policy.failed_attempts.saturating_add(1);
    policy.last_attempt_at = Some(now);

    if policy.failed_attempts >= policy.max_attempts {
        let passes = policy.shred_passes;
        let target_buf = target.to_path_buf();
        let _ = shred_file(target, passes);
        let _ = fs::remove_file(&policy_path);
        Ok(GuardAction::SelfShredTriggered {
            reason: ShredReason::MaxAttemptsExceeded {
                attempts: policy.failed_attempts,
                limit: policy.max_attempts,
            },
            passes,
            target_path: target_buf,
        })
    } else {
        let remaining = policy.max_attempts.saturating_sub(policy.failed_attempts);
        save_policy(&policy_path, &mut policy)?;
        Ok(GuardAction::AttemptFailed {
            failed_attempts: policy.failed_attempts,
            max_attempts: policy.max_attempts,
            remaining,
        })
    }
}

/// Record a successful passphrase attempt, resetting failed counter to zero.
pub fn record_success(target: &Path, at_time: Option<u64>) -> Result<Option<GuardPolicy>> {
    let (policy_path, mut policy) = match find_guard(target)? {
        Some(pair) => pair,
        None => return Ok(None),
    };

    if !policy.active {
        return Ok(None);
    }

    let now = at_time.unwrap_or_else(current_utc_timestamp);
    policy.failed_attempts = 0;
    policy.last_success_at = Some(now);
    policy.last_attempt_at = Some(now);

    // Refresh dead-man deadline if interval is configured
    if let Some(interval) = policy.dead_man_interval_seconds {
        policy.dead_man_deadline = Some(now.saturating_add(interval));
    }

    save_policy(&policy_path, &mut policy)?;
    Ok(Some(policy))
}

/// Reset failed attempts counter and refresh dead-man deadline.
pub fn reset_guard(target: &Path, at_time: Option<u64>) -> Result<GuardPolicy> {
    let (policy_path, mut policy) = find_guard(target)?
        .ok_or_else(|| Error::Format(format!("no guard active for {}", target.display())))?;

    let now = at_time.unwrap_or_else(current_utc_timestamp);
    policy.failed_attempts = 0;
    if let Some(interval) = policy.dead_man_interval_seconds {
        policy.dead_man_deadline = Some(now.saturating_add(interval));
    }

    save_policy(&policy_path, &mut policy)?;
    Ok(policy)
}

/// Check-in dead-man's switch to extend expiration deadline.
pub fn checkin_guard(
    target: &Path,
    new_interval: Option<u64>,
    at_time: Option<u64>,
) -> Result<GuardPolicy> {
    let (policy_path, mut policy) = find_guard(target)?
        .ok_or_else(|| Error::Format(format!("no guard active for {}", target.display())))?;

    let now = at_time.unwrap_or_else(current_utc_timestamp);
    let interval = new_interval
        .or(policy.dead_man_interval_seconds)
        .ok_or_else(|| {
            Error::Format("no dead-man switch interval configured for this vault".into())
        })?;

    policy.dead_man_interval_seconds = Some(interval);
    policy.dead_man_deadline = Some(now.saturating_add(interval));
    policy.last_success_at = Some(now);

    save_policy(&policy_path, &mut policy)?;
    Ok(policy)
}

/// Disarm and remove guard policy for target.
pub fn disarm_guard(target: &Path) -> Result<bool> {
    match find_guard(target)? {
        Some((path, _)) => {
            fs::remove_file(path)?;
            Ok(true)
        }
        None => Ok(false),
    }
}

/// Manually trigger immediate emergency multi-pass self-shred.
pub fn emergency_trigger(target: &Path, passes: u8) -> Result<u64> {
    let _ = disarm_guard(target);
    shred_file(target, passes)
}

/// Inspect guard status for report generation.
pub fn inspect_guard(target: &Path, at_time: Option<u64>) -> Result<Option<GuardStatusReport>> {
    let (path, policy) = match find_guard(target)? {
        Some(pair) => pair,
        None => return Ok(None),
    };

    let now = at_time.unwrap_or_else(current_utc_timestamp);
    let remaining_attempts = policy.max_attempts.saturating_sub(policy.failed_attempts);

    let (dead_man_rem, dead_man_exp) = match policy.dead_man_deadline {
        Some(dl) => {
            let diff = dl as i64 - now as i64;
            (Some(diff), diff <= 0)
        }
        None => (None, false),
    };

    Ok(Some(GuardStatusReport {
        target: target.display().to_string(),
        active: policy.active,
        max_attempts: policy.max_attempts,
        failed_attempts: policy.failed_attempts,
        remaining_attempts,
        shred_passes: policy.shred_passes,
        created_at: policy.created_at,
        created_at_iso: format_iso8601_utc(policy.created_at),
        last_attempt_at: policy.last_attempt_at,
        last_attempt_iso: policy.last_attempt_at.map(format_iso8601_utc),
        last_success_at: policy.last_success_at,
        last_success_iso: policy.last_success_at.map(format_iso8601_utc),
        dead_man_deadline: policy.dead_man_deadline,
        dead_man_deadline_iso: policy.dead_man_deadline.map(format_iso8601_utc),
        dead_man_remaining_seconds: dead_man_rem,
        dead_man_expired: dead_man_exp,
        companion: policy.companion,
        guard_file_path: path.display().to_string(),
    }))
}

/// Enumerate all active stealth guard ledgers.
pub fn list_guards(at_time: Option<u64>) -> Result<Vec<GuardStatusReport>> {
    let mut reports = Vec::new();
    let dir = stealth_ledger_dir();
    if dir.exists() {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("guard") {
                if let Ok(policy) = load_policy(&path) {
                    let target = PathBuf::from(&policy.target_path);
                    if let Ok(Some(rep)) = inspect_guard(&target, at_time) {
                        reports.push(rep);
                    }
                }
            }
        }
    }
    Ok(reports)
}
